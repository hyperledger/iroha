//! The one canonical verifier of a genesis-declared physical dataspace route.
//!
//! The physical Nexus catalog (lanes, dataspaces, routing rules and the autoscale range) is
//! fixed at genesis: signed genesis commits the Nexus/AMX context hash, every node refuses a
//! genesis whose staged context differs, and later catalog transitions are additive only. The
//! native lane policy, by contrast, is a governed custom parameter, so a light client must
//! recheck it at every certified cut it relies on.
//!
//! [`verify_genesis_dataspace_v1`] binds one dataspace selector to an authenticated signed
//! genesis and its exact context preimage; [`GenesisDataspaceAuthorityV1::verify_cut`]
//! rechecks the governed lane policy and the runtime catalog at one certified World cut.
use super::{AuthenticatedSignedGenesisV1, VerifiedSumeragiBlock, VerifiedWorldStateSnapshotV1};
use crate::{
    NetworkId,
    block::{BlockHeader, consensus::SumeragiRootScope},
    isi::SetParameter,
    nexus::{
        LaneLifecycleParameterV1, LaneVisibility, MAX_NEXUS_AMX_CONTEXT_BYTES_V1,
        NexusAmxContextCatalogV1, NexusAmxContextError, NexusCatalogTransitionV1,
        NexusRuntimeCatalogV1, decode_nexus_amx_context_v1,
    },
    parameter::{CustomParameter, Parameter, Parameters},
    sns::dataspace_id_for_alias,
    sumeragi_lanes::SumeragiLanePolicy,
    transaction::Executable,
};
use iroha_crypto::{Hash, HashOf, PublicKey};
use iroha_model_base::{
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

/// Diagnostic projection schema of a verified genesis dataspace authority.
pub const GENESIS_DATASPACE_VERIFICATION_SCHEMA_V1: &str =
    "iroha.genesis-dataspace-verification.v1";
const MAX_ACCOUNT_ROUTES: usize = 64;

/// The dataspace a light client expects genesis to declare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisDataspaceSelectorV1 {
    /// SNS dataspace alias.
    pub alias: String,
    /// Expected dataspace identity (the SNS dataspace-alias name hash).
    pub dataspace_id: DataSpaceId,
    /// The dataspace's sole physical lane (never lane 0).
    pub lane_id: LaneId,
    /// Expected lane alias.
    pub lane_alias: String,
    /// Expected lane visibility.
    pub visibility: LaneVisibility,
    /// Account matchers that must route to the lane through explicit physical rules.
    ///
    /// Each must be scoped to the dataspace namespace (`label@alias` or `label@ns.alias`).
    /// An empty list means the dataspace routes by target dataspace only.
    pub account_routes: Vec<String>,
}

/// Why a genesis dataspace declaration or certified cut was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenesisDataspaceError {
    /// The selector itself is malformed.
    #[error("genesis dataspace selector is invalid: {0}")]
    Selector(&'static str),
    /// Signed genesis is not a Global root.
    #[error("signed genesis is not a Global root")]
    NotGlobalRoot,
    /// The preimage does not hash to the signed Nexus/AMX context commitment.
    #[error("Nexus/AMX context preimage differs from the signed genesis commitment")]
    ContextHash,
    /// The preimage is not a valid context.
    #[error(transparent)]
    Context(#[from] NexusAmxContextError),
    /// The dataspace catalog differs from the selector.
    #[error("genesis dataspace catalog differs: {0}")]
    Dataspace(&'static str),
    /// The lane catalog differs from the selector.
    #[error("genesis lane catalog differs: {0}")]
    Lane(&'static str),
    /// The physical routing policy can divert the dataspace.
    #[error("genesis routing policy differs: {0}")]
    Routing(&'static str),
    /// The governed native lane policy differs.
    #[error("native lane policy differs: {0}")]
    LanePolicy(String),
    /// Genesis mutates the Nexus catalog during execution.
    #[error("signed genesis mutates the Nexus catalog")]
    CatalogMutation,
    /// The certified cut differs from this authority.
    #[error("certified cut differs: {0}")]
    Cut(String),
    /// The committed runtime catalog collides with the declared dataspace.
    #[error("runtime catalog collides with the genesis dataspace: {0}")]
    RuntimeCatalog(&'static str),
    /// A Restricted dataspace needs a per-height manifest witness that does not exist yet.
    #[error("restricted dataspace manifest authority is unavailable")]
    RestrictedManifestAuthorityUnavailable,
}

/// One genesis-declared dataspace route, verified against signed genesis and its context.
///
/// It carries only values derived from the authenticated originals and has no decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisDataspaceAuthorityV1 {
    network_id: NetworkId,
    chain_id: String,
    genesis_hash: HashOf<BlockHeader>,
    signed_genesis_sha256: [u8; 32],
    genesis_public_key: PublicKey,
    nexus_amx_context_hash: Hash,
    nexus_amx_context_sha256: [u8; 32],
    dataspace_alias: String,
    dataspace_id: DataSpaceId,
    lane_id: LaneId,
    lane_alias: String,
    visibility: LaneVisibility,
    account_routes: Vec<String>,
}

/// A certified World cut at which the governed lane policy still serves the dataspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGenesisDataspaceCutV1 {
    height: u64,
    context_id: Hash,
    dataspace_id: DataSpaceId,
    lane_id: LaneId,
    committee: Vec<PeerId>,
}

impl VerifiedGenesisDataspaceCutV1 {
    /// Certified height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }
    /// Certified context identity.
    #[must_use]
    pub fn context_id(&self) -> Hash {
        self.context_id
    }
    /// The verified dataspace.
    #[must_use]
    pub fn dataspace_id(&self) -> DataSpaceId {
        self.dataspace_id
    }
    /// The verified lane.
    #[must_use]
    pub fn lane_id(&self) -> LaneId {
        self.lane_id
    }
    /// The lane committee pinned by the governed policy at this cut.
    #[must_use]
    pub fn committee(&self) -> &[PeerId] {
        &self.committee
    }
}

/// Whether an account matcher (`label@namespace`) is scoped to the dataspace `alias`.
fn scoped_to(matcher: &str, alias: &str) -> bool {
    matcher.rsplit_once('@').is_some_and(|(_, namespace)| {
        let namespace = namespace.trim().to_ascii_lowercase();
        namespace == alias
            || namespace
                .strip_suffix(alias)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn check_selector(selector: &GenesisDataspaceSelectorV1) -> Result<(), GenesisDataspaceError> {
    use GenesisDataspaceError::Selector;
    if dataspace_id_for_alias(&selector.alias) != Some(selector.dataspace_id)
        || selector.dataspace_id == DataSpaceId::UNIVERSAL
    {
        return Err(Selector(
            "dataspace id is not the SNS name hash of its alias",
        ));
    }
    if selector.lane_id.as_u32() == 0 || selector.lane_alias.trim().is_empty() {
        return Err(Selector("the dataspace lane must be a named non-zero lane"));
    }
    let mut routes = BTreeSet::new();
    if selector.account_routes.len() > MAX_ACCOUNT_ROUTES
        || selector
            .account_routes
            .iter()
            .any(|route| !scoped_to(route, &selector.alias) || !routes.insert(route.as_str()))
    {
        return Err(Selector(
            "account routes must be distinct and scoped to the dataspace namespace",
        ));
    }
    Ok(())
}

fn check_routing(
    catalog: &NexusAmxContextCatalogV1,
    selector: &GenesisDataspaceSelectorV1,
) -> Result<(), GenesisDataspaceError> {
    use GenesisDataspaceError::Routing;
    let (lane, dataspace) = (selector.lane_id, selector.dataspace_id);
    let rules = catalog.rules();
    let mut last_required = None;
    for route in &selector.account_routes {
        let index = rules
            .iter()
            .position(|rule| {
                rule.account() == Some(route.as_str())
                    && rule.instruction().is_none()
                    && rule.lane() == lane
                    && rule.dataspace() == Some(dataspace)
            })
            .ok_or(Routing("a required account route has no exact rule"))?;
        last_required = last_required.max(Some(index));
    }
    // Physical routing is first-match: nothing before the last required route may match the
    // dataspace's accounts. Only wildcard rules for foreign namespaces can precede it.
    if let Some(last) = last_required {
        for rule in &rules[..last] {
            let required = rule
                .account()
                .is_some_and(|account| selector.account_routes.iter().any(|r| r == account));
            let foreign_wildcard = rule.account().is_some_and(|account| {
                account.starts_with("*@") && !scoped_to(account, &selector.alias)
            });
            if !required && !foreign_wildcard {
                return Err(Routing("a rule can shadow a required account route"));
            }
        }
    }
    for rule in rules {
        if rule
            .account()
            .is_some_and(|account| scoped_to(account, &selector.alias))
            && (rule.lane() != lane || rule.dataspace() != Some(dataspace))
        {
            return Err(Routing(
                "a dataspace-scoped account rule targets another route",
            ));
        }
        if (rule.lane() == lane && rule.dataspace().is_some_and(|other| other != dataspace))
            || (rule.dataspace() == Some(dataspace) && rule.lane() != lane)
        {
            return Err(Routing(
                "a rule pairs the lane or dataspace with another route",
            ));
        }
    }
    if (catalog.default_lane() == lane) != (catalog.default_dataspace() == dataspace) {
        return Err(Routing(
            "the routing default splits the lane from its dataspace",
        ));
    }
    Ok(())
}

/// Check the governed lane policy; returns the lane's pinned committee.
fn check_lane_policy(
    policy: &SumeragiLanePolicy,
    selector_alias: &str,
    dataspace: DataSpaceId,
    lane: LaneId,
    account_routes: &[String],
    committee: &BTreeSet<&PeerId>,
) -> Result<Vec<PeerId>, GenesisDataspaceError> {
    let fail = |reason: &str| Err(GenesisDataspaceError::LanePolicy(reason.to_owned()));
    let Some(fixed) = policy.fixed_lane(lane) else {
        return fail("the dataspace lane is not a fixed lane");
    };
    if fixed.dataspace != dataspace {
        return fail("the fixed lane serves another dataspace");
    }
    if policy
        .fixed
        .iter()
        .any(|other| other.dataspace == dataspace && other.lane != lane)
        || policy
            .autoscale
            .as_ref()
            .is_some_and(|autoscale| autoscale.dataspace == dataspace)
        || policy.is_elastic(lane)
    {
        return fail("another fixed or elastic lane serves the dataspace");
    }
    if fixed
        .committee
        .iter()
        .any(|member| !committee.contains(&member.peer))
    {
        return fail("the lane committee is not drawn from the global committee");
    }
    for route in &policy.routes {
        let Some(account) = route.account.as_deref() else {
            continue;
        };
        if (account_routes.iter().any(|r| r == account) || scoped_to(account, selector_alias))
            && route.lane != lane
        {
            return fail("a native route diverts the dataspace's accounts");
        }
    }
    Ok(fixed
        .committee
        .iter()
        .map(|member| member.peer.clone())
        .collect())
}

fn decode_lane_policy(
    custom: &CustomParameter,
) -> Result<SumeragiLanePolicy, GenesisDataspaceError> {
    SumeragiLanePolicy::from_custom_parameter(custom)
        .ok_or_else(|| GenesisDataspaceError::LanePolicy("not a lane policy".to_owned()))?
        .map_err(GenesisDataspaceError::LanePolicy)
}

/// Verify that authenticated signed genesis declares the selected dataspace and its lane.
///
/// # Errors
/// A malformed selector; a non-Global root; a preimage that does not hash to the signed
/// context or is not a valid context; a dataspace, lane, autoscale or routing catalog that
/// differs from the selector or can divert it; a missing, repeated or mismatched native lane
/// policy; or any catalog transition, lane lifecycle or runtime catalog parameter in genesis.
pub fn verify_genesis_dataspace_v1(
    genesis: &AuthenticatedSignedGenesisV1,
    amx_preimage: &[u8],
    selector: &GenesisDataspaceSelectorV1,
) -> Result<GenesisDataspaceAuthorityV1, GenesisDataspaceError> {
    check_selector(selector)?;
    let context = &genesis.metadata().sumeragi_context;
    if context.root_scope != SumeragiRootScope::Global {
        return Err(GenesisDataspaceError::NotGlobalRoot);
    }
    if amx_preimage.is_empty()
        || amx_preimage.len() > MAX_NEXUS_AMX_CONTEXT_BYTES_V1
        || Hash::new(amx_preimage) != Hash::prehashed(context.nexus_amx_context_hash)
    {
        return Err(GenesisDataspaceError::ContextHash);
    }
    let catalog = decode_nexus_amx_context_v1(amx_preimage)?;
    let mut named = catalog
        .dataspaces()
        .iter()
        .filter(|dataspace| dataspace.alias() == selector.alias);
    let (Some(dataspace), None) = (named.next(), named.next()) else {
        return Err(GenesisDataspaceError::Dataspace(
            "the alias is not declared exactly once",
        ));
    };
    if dataspace.id() != selector.dataspace_id {
        return Err(GenesisDataspaceError::Dataspace(
            "the declared identity differs from the selected SNS identity",
        ));
    }
    let mut lanes = catalog
        .lanes()
        .iter()
        .filter(|lane| lane.dataspace_id() == selector.dataspace_id);
    let (Some(lane), None) = (lanes.next(), lanes.next()) else {
        return Err(GenesisDataspaceError::Lane(
            "the dataspace does not own exactly one lane",
        ));
    };
    if lane.id() != selector.lane_id
        || lane.alias() != selector.lane_alias
        || lane.visibility() != selector.visibility
    {
        return Err(GenesisDataspaceError::Lane(
            "the dataspace lane id, alias or visibility differs",
        ));
    }
    if catalog.autoscale().contains(selector.lane_id) {
        return Err(GenesisDataspaceError::Lane(
            "the dataspace lane lies in the autoscale range",
        ));
    }
    check_routing(&catalog, selector)?;
    let mut policies = Vec::new();
    for transaction in genesis.block().external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(GenesisDataspaceError::CatalogMutation);
        };
        for instruction in instructions {
            let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            let Parameter::Custom(custom) = set.inner() else {
                continue;
            };
            if [
                NexusCatalogTransitionV1::parameter_id(),
                LaneLifecycleParameterV1::parameter_id(),
                NexusRuntimeCatalogV1::parameter_id(),
            ]
            .contains(custom.id())
            {
                return Err(GenesisDataspaceError::CatalogMutation);
            }
            if custom.id() == &SumeragiLanePolicy::parameter_id() {
                policies.push(decode_lane_policy(custom)?);
            }
        }
    }
    let [policy] = policies.as_slice() else {
        return Err(GenesisDataspaceError::LanePolicy(
            "genesis must set exactly one lane policy".to_owned(),
        ));
    };
    let committee = genesis
        .epoch()
        .committee
        .iter()
        .map(|member| &member.validator)
        .collect();
    check_lane_policy(
        policy,
        &selector.alias,
        selector.dataspace_id,
        selector.lane_id,
        &selector.account_routes,
        &committee,
    )?;
    let pins = genesis.pins();
    Ok(GenesisDataspaceAuthorityV1 {
        network_id: pins.network_id,
        chain_id: pins.chain_id.clone(),
        genesis_hash: pins.genesis_hash,
        signed_genesis_sha256: genesis.signed_genesis_sha256(),
        genesis_public_key: pins.genesis_public_key.clone(),
        nexus_amx_context_hash: Hash::prehashed(context.nexus_amx_context_hash),
        nexus_amx_context_sha256: Sha256::digest(amx_preimage).into(),
        dataspace_alias: selector.alias.clone(),
        dataspace_id: selector.dataspace_id,
        lane_id: selector.lane_id,
        lane_alias: selector.lane_alias.clone(),
        visibility: selector.visibility,
        account_routes: selector.account_routes.clone(),
    })
}

impl GenesisDataspaceAuthorityV1 {
    /// Recheck the governed lane policy and the runtime catalog at one certified World cut.
    ///
    /// `parameters` is the complete `world.parameters` value read for the same cut; it is
    /// authenticated here against the certified snapshot.
    ///
    /// # Errors
    /// Restricted visibility (no manifest witness exists yet); a snapshot of another height or
    /// context; a tip outside this authority's Global network and chain; parameters that differ
    /// from the certified cell; a missing or invalid lane policy, or one that no longer pins the
    /// lane to the dataspace with a committee drawn from the tip committee; or a runtime catalog
    /// addition of this dataspace or of a manifest for its lane.
    pub fn verify_cut(
        &self,
        tip: &VerifiedSumeragiBlock,
        world: &VerifiedWorldStateSnapshotV1,
        parameters: &Parameters,
    ) -> Result<VerifiedGenesisDataspaceCutV1, GenesisDataspaceError> {
        let cut = |error: &dyn std::fmt::Display| GenesisDataspaceError::Cut(error.to_string());
        if self.visibility != LaneVisibility::Public {
            return Err(GenesisDataspaceError::RestrictedManifestAuthorityUnavailable);
        }
        if world.height() != tip.height() || world.context_id() != tip.context_id() {
            return Err(cut(&"the World snapshot belongs to another certified cut"));
        }
        tip.verify_global_scope(self.network_id, &self.chain_id)
            .map_err(|error| cut(&error))?;
        world
            .verify_cell_value("world.parameters", parameters)
            .map_err(|error| cut(&error))?;
        let policy = parameters
            .custom()
            .get(&SumeragiLanePolicy::parameter_id())
            .ok_or_else(|| GenesisDataspaceError::LanePolicy("the lane policy is absent".into()))
            .and_then(decode_lane_policy)?;
        let committee = tip
            .commitment()
            .schedule
            .current
            .committee
            .iter()
            .map(|member| &member.validator)
            .collect();
        let lane_committee = check_lane_policy(
            &policy,
            &self.dataspace_alias,
            self.dataspace_id,
            self.lane_id,
            &self.account_routes,
            &committee,
        )?;
        if let Some(custom) = parameters
            .custom()
            .get(&NexusRuntimeCatalogV1::parameter_id())
        {
            let runtime = NexusRuntimeCatalogV1::from_custom_parameter(custom)
                .map_err(|_| GenesisDataspaceError::RuntimeCatalog("invalid runtime catalog"))?
                .ok_or(GenesisDataspaceError::RuntimeCatalog(
                    "invalid runtime catalog",
                ))?;
            if runtime.dataspaces.iter().any(|addition| {
                addition.descriptor.id == self.dataspace_id
                    || addition.descriptor.alias == self.dataspace_alias
            }) {
                return Err(GenesisDataspaceError::RuntimeCatalog(
                    "a runtime dataspace addition reuses the identity or alias",
                ));
            }
            if runtime
                .manifests
                .iter()
                .any(|manifest| manifest.lane_id == self.lane_id)
            {
                return Err(GenesisDataspaceError::RuntimeCatalog(
                    "a runtime manifest addition targets the lane",
                ));
            }
        }
        Ok(VerifiedGenesisDataspaceCutV1 {
            height: tip.height(),
            context_id: tip.context_id(),
            dataspace_id: self.dataspace_id,
            lane_id: self.lane_id,
            committee: lane_committee,
        })
    }

    /// Genesis-derived network.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Chain label.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// Signed genesis header hash.
    #[must_use]
    pub fn genesis_hash(&self) -> HashOf<BlockHeader> {
        self.genesis_hash
    }
    /// SHA-256 of the exact framed signed genesis bytes.
    #[must_use]
    pub fn signed_genesis_sha256(&self) -> [u8; 32] {
        self.signed_genesis_sha256
    }
    /// Genesis signing authority.
    #[must_use]
    pub fn genesis_public_key(&self) -> &PublicKey {
        &self.genesis_public_key
    }
    /// Signed Nexus/AMX context commitment.
    #[must_use]
    pub fn nexus_amx_context_hash(&self) -> Hash {
        self.nexus_amx_context_hash
    }
    /// SHA-256 of the exact context preimage.
    #[must_use]
    pub fn nexus_amx_context_sha256(&self) -> [u8; 32] {
        self.nexus_amx_context_sha256
    }
    /// Dataspace alias.
    #[must_use]
    pub fn dataspace_alias(&self) -> &str {
        &self.dataspace_alias
    }
    /// Dataspace identity.
    #[must_use]
    pub fn dataspace_id(&self) -> DataSpaceId {
        self.dataspace_id
    }
    /// The dataspace's lane.
    #[must_use]
    pub fn lane_id(&self) -> LaneId {
        self.lane_id
    }
    /// Lane alias.
    #[must_use]
    pub fn lane_alias(&self) -> &str {
        &self.lane_alias
    }
    /// Lane visibility.
    #[must_use]
    pub fn visibility(&self) -> LaneVisibility {
        self.visibility
    }
    /// Required explicit account routes.
    #[must_use]
    pub fn account_routes(&self) -> &[String] {
        &self.account_routes
    }

    /// Canonical diagnostic projection (sorted keys, compact). It is never authority input.
    ///
    /// # Errors
    /// Only if the genesis key cannot be rendered.
    pub fn projection_json(&self) -> Result<String, norito::json::Error> {
        use norito::json::Value;
        let text = |value: &str| Value::String(value.to_owned());
        let mut map = norito::json::Map::new();
        map.insert(
            "account_routes".into(),
            Value::Array(self.account_routes.iter().map(|r| text(r)).collect()),
        );
        map.insert("chain_id".into(), text(&self.chain_id));
        map.insert("dataspace_alias".into(), text(&self.dataspace_alias));
        map.insert(
            "dataspace_id".into(),
            text(&self.dataspace_id.as_u64().to_string()),
        );
        map.insert(
            "genesis_block_hash".into(),
            text(&hex::encode(self.genesis_hash.as_ref())),
        );
        map.insert(
            "genesis_public_key".into(),
            text(&self.genesis_public_key.to_string()),
        );
        map.insert("lane_alias".into(), text(&self.lane_alias));
        map.insert(
            "lane_id".into(),
            Value::from(u64::from(self.lane_id.as_u32())),
        );
        map.insert("network_id".into(), text(&self.network_id.to_string()));
        map.insert(
            "nexus_amx_context_hash".into(),
            text(&hex::encode(self.nexus_amx_context_hash.as_ref())),
        );
        map.insert(
            "nexus_amx_context_sha256".into(),
            text(&hex::encode(self.nexus_amx_context_sha256)),
        );
        map.insert(
            "schema".into(),
            text(GENESIS_DATASPACE_VERIFICATION_SCHEMA_V1),
        );
        map.insert(
            "signed_genesis_sha256".into(),
            text(&hex::encode(self.signed_genesis_sha256)),
        );
        map.insert("visibility".into(), text(self.visibility.as_str()));
        norito::json::to_string(&Value::Object(map))
    }
}

#[cfg(test)]
#[path = "genesis_dataspace_tests.rs"]
mod tests;
