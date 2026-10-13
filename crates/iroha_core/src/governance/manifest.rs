//! Lane governance manifest loading utilities.
//!
//! These helpers validate that lanes which advertise a governance module in the
//! Nexus catalog have an authenticated frozen manifest source and thread the parsed rules
//! into runtime enforcement (queue admission, governance telemetry, etc.).
use crate::secure_file_metadata::{self, SecureMetadata};
use hex::decode;
use iroha_config::parameters::actual::{
    GovernanceCatalog, GovernanceModule as ConfigGovernanceModule, LaneRegistry,
};
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
use iroha_crypto::privacy::CommitmentScheme;
use iroha_crypto::{
    Hash,
    privacy::{LaneCommitmentId, LanePrivacyCommitment, MerkleCommitment},
};
use iroha_data_model::{
    account::AccountId,
    nexus::{
        AUTOSCALE_META_COMMITTEE, AUTOSCALE_META_CREATED_HEIGHT, AUTOSCALE_META_DRAIN_STATE,
        AUTOSCALE_META_MANAGED, LaneCatalog, LaneConfig, LaneStorageProfile, LaneVisibility,
        NativeLaneManifestV1,
    },
};
use iroha_logger::{debug, info, warn};
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use norito::{
    codec::Encode,
    json::{self, JsonDeserialize, JsonSerialize, Value as JsonValue},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fmt, fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
    str::{self, FromStr},
    sync::Arc,
};
/// First-release byte ceiling for one active lane manifest source.
const LANE_MANIFEST_MAX_BYTES_V1: usize = 256 * 1024;
/// First-release byte ceiling for the optional governance catalog overlay.
const GOVERNANCE_OVERLAY_MAX_BYTES_V1: usize = 512 * 1024;
/// First-release byte ceiling across all accepted active manifests and the overlay.
const MANIFEST_SOURCE_AGGREGATE_MAX_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum raw bytes inside one JSON string literal before typed allocation.
const MANIFEST_SOURCE_MAX_STRING_BYTES_V1: usize = 4 * 1024;
/// Maximum string literals accepted in one source before typed allocation.
const MANIFEST_SOURCE_MAX_STRINGS_V1: usize = 4 * 1024;
/// Maximum cumulative raw string bytes accepted in one source.
const MANIFEST_SOURCE_MAX_STRING_BYTES_TOTAL_V1: usize = 192 * 1024;
/// Maximum structural rule/value units accepted in one source.
const MANIFEST_SOURCE_MAX_RULE_UNITS_V1: usize = 8 * 1024;
/// Maximum JSON container depth accepted by lane-manifest sources.
const MANIFEST_SOURCE_MAX_JSON_DEPTH_V1: usize = 32;
/// Aggregate first-release ceiling for retained source string literals.
const MANIFEST_SOURCE_AGGREGATE_MAX_STRINGS_V1: usize = 128 * 1024;
/// Aggregate first-release ceiling for retained source string bytes.
const MANIFEST_SOURCE_AGGREGATE_MAX_STRING_BYTES_V1: usize = 8 * 1024 * 1024;
/// Aggregate first-release ceiling for retained structural rule/value units.
const MANIFEST_SOURCE_AGGREGATE_MAX_RULE_UNITS_V1: usize = 128 * 1024;
/// Maximum canonical JSON size admitted after bounded typed parsing.
const LANE_MANIFEST_MAX_CANONICAL_BYTES_V1: usize = 512 * 1024;
/// Maximum canonical overlay size admitted after bounded typed parsing.
const GOVERNANCE_OVERLAY_MAX_CANONICAL_BYTES_V1: usize = 1024 * 1024;
/// Maximum active lane alias/module/key identifier width.
const MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1: usize = 128;
/// Maximum account or peer identity literal width.
const MANIFEST_SOURCE_MAX_IDENTITY_BYTES_V1: usize = 512;
/// Maximum Torii URL, module parameter, or hook string width.
pub const MANIFEST_SOURCE_MAX_VALUE_BYTES_V1: usize = 4 * 1024;
/// Maximum validator bindings in one lane manifest.
pub const LANE_MANIFEST_MAX_VALIDATORS_V1: usize = 256;
/// Maximum protected namespaces in one lane manifest.
const LANE_MANIFEST_MAX_PROTECTED_NAMESPACES_V1: usize = 512;
/// Maximum top-level hook declarations in one lane manifest.
const LANE_MANIFEST_MAX_HOOKS_V1: usize = 128;
/// Maximum privacy commitments in one lane manifest.
const LANE_MANIFEST_MAX_PRIVACY_COMMITMENTS_V1: usize = 256;
/// Maximum modules declared by the governance overlay.
const GOVERNANCE_OVERLAY_MAX_MODULES_V1: usize = 256;
/// Maximum parameters declared by one governance module.
const GOVERNANCE_OVERLAY_MAX_PARAMS_PER_MODULE_V1: usize = 128;
/// Maximum parameters across the complete governance overlay.
const GOVERNANCE_OVERLAY_MAX_PARAMS_V1: usize = 4 * 1024;
const MANIFEST_JSON_LIMITS_V1: ManifestJsonLimits = ManifestJsonLimits {
    max_string_bytes: MANIFEST_SOURCE_MAX_STRING_BYTES_V1,
    max_strings: MANIFEST_SOURCE_MAX_STRINGS_V1,
    max_total_string_bytes: MANIFEST_SOURCE_MAX_STRING_BYTES_TOTAL_V1,
    max_rule_units: MANIFEST_SOURCE_MAX_RULE_UNITS_V1,
    max_depth: MANIFEST_SOURCE_MAX_JSON_DEPTH_V1,
};
#[derive(Clone, Copy, Debug)]
struct ManifestJsonLimits {
    max_string_bytes: usize,
    max_strings: usize,
    max_total_string_bytes: usize,
    max_rule_units: usize,
    max_depth: usize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ManifestJsonFootprint {
    strings: usize,
    string_bytes: usize,
    rule_units: usize,
}
#[derive(Debug, Default)]
struct ManifestSourceLoadBudget {
    bytes: usize,
    strings: usize,
    string_bytes: usize,
    rule_units: usize,
}
impl ManifestSourceLoadBudget {
    fn remaining_bytes(&self) -> usize {
        MANIFEST_SOURCE_AGGREGATE_MAX_BYTES_V1.saturating_sub(self.bytes)
    }
    fn charge_bytes(&mut self, bytes: usize) -> Result<(), String> {
        let attempted = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| "lane-manifest aggregate source-byte counter overflowed".to_owned())?;
        if attempted > MANIFEST_SOURCE_AGGREGATE_MAX_BYTES_V1 {
            return Err(format!(
                "lane-manifest aggregate source bytes {attempted} exceed first-release limit {MANIFEST_SOURCE_AGGREGATE_MAX_BYTES_V1}"
            ));
        }
        self.bytes = attempted;
        Ok(())
    }
    fn charge_json(&mut self, footprint: ManifestJsonFootprint) -> Result<(), String> {
        let strings = self
            .strings
            .checked_add(footprint.strings)
            .ok_or_else(|| "lane-manifest aggregate string counter overflowed".to_owned())?;
        if strings > MANIFEST_SOURCE_AGGREGATE_MAX_STRINGS_V1 {
            return Err(format!(
                "lane-manifest aggregate string count {strings} exceeds first-release limit {MANIFEST_SOURCE_AGGREGATE_MAX_STRINGS_V1}"
            ));
        }
        let string_bytes = self
            .string_bytes
            .checked_add(footprint.string_bytes)
            .ok_or_else(|| "lane-manifest aggregate string-byte counter overflowed".to_owned())?;
        if string_bytes > MANIFEST_SOURCE_AGGREGATE_MAX_STRING_BYTES_V1 {
            return Err(format!(
                "lane-manifest aggregate string bytes {string_bytes} exceed first-release limit {MANIFEST_SOURCE_AGGREGATE_MAX_STRING_BYTES_V1}"
            ));
        }
        let rule_units = self
            .rule_units
            .checked_add(footprint.rule_units)
            .ok_or_else(|| "lane-manifest aggregate rule counter overflowed".to_owned())?;
        if rule_units > MANIFEST_SOURCE_AGGREGATE_MAX_RULE_UNITS_V1 {
            return Err(format!(
                "lane-manifest aggregate rule units {rule_units} exceed first-release limit {MANIFEST_SOURCE_AGGREGATE_MAX_RULE_UNITS_V1}"
            ));
        }
        self.strings = strings;
        self.string_bytes = string_bytes;
        self.rule_units = rule_units;
        Ok(())
    }
}
/// Governance catalog overlay loaded from distribution cache.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize, Default)]
#[norito(deny_unknown_fields)]
struct GovernanceCatalogFile {
    /// Default governance module identifier applied when lanes omit an override.
    pub default_module: Option<String>,
    /// Registered governance modules keyed by name.
    #[norito(default)]
    pub modules: BTreeMap<String, GovernanceModuleFile>,
}
/// Governance module descriptor loaded from distribution cache.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize, Default)]
#[norito(deny_unknown_fields)]
struct GovernanceModuleFile {
    /// Module type (e.g., `parliament`, `stake_weighted`).
    pub module_type: Option<String>,
    /// Additional parameters defined by the module.
    #[norito(default)]
    pub params: BTreeMap<String, String>,
}
impl From<GovernanceModuleFile> for ConfigGovernanceModule {
    fn from(value: GovernanceModuleFile) -> Self {
        Self {
            module_type: value.module_type,
            params: value.params,
        }
    }
}
/// Status of a lane manifest after loading from disk.
#[derive(Debug, Clone)]
pub struct LaneManifestStatus {
    /// Lane identifier.
    pub lane: LaneId,
    /// Human-readable alias.
    pub alias: String,
    /// Dataspace binding derived from the lane catalog.
    pub dataspace: DataSpaceId,
    /// Declarative visibility profile.
    pub visibility: LaneVisibility,
    /// Storage profile advertised by the lane.
    pub storage: LaneStorageProfile,
    /// Governance module configured in the lane catalog.
    pub governance: Option<String>,
    /// Filesystem source path; authenticated runtime manifests have no path.
    pub manifest_path: Option<PathBuf>,
    /// Parsed governance rules derived from the manifest.
    pub governance_rules: Option<GovernanceRules>,
    /// Lane privacy commitments derived from the manifest.
    pub privacy_commitments: Vec<LanePrivacyCommitment>,
}
impl LaneManifestStatus {
    fn missing(
        lane: LaneId,
        alias: String,
        dataspace: DataSpaceId,
        visibility: LaneVisibility,
        storage: LaneStorageProfile,
        governance: Option<String>,
    ) -> Self {
        Self {
            lane,
            alias,
            dataspace,
            visibility,
            storage,
            governance,
            manifest_path: None,
            governance_rules: None,
            privacy_commitments: Vec::new(),
        }
    }
    fn builder(
        lane: LaneId,
        alias: String,
        dataspace: DataSpaceId,
        visibility: LaneVisibility,
        storage: LaneStorageProfile,
    ) -> LaneManifestStatusBuilder {
        LaneManifestStatusBuilder::new(lane, alias, dataspace, visibility, storage)
    }
    /// Retrieve parsed governance rules if available.
    #[must_use]
    pub fn rules(&self) -> Option<&GovernanceRules> {
        self.governance_rules.as_ref()
    }
    /// Privacy commitments advertised by the lane manifest.
    #[must_use]
    pub fn privacy_commitments(&self) -> &[LanePrivacyCommitment] {
        &self.privacy_commitments
    }
}
#[derive(Debug)]
struct LaneManifestStatusBuilder {
    lane: LaneId,
    alias: String,
    dataspace: DataSpaceId,
    visibility: LaneVisibility,
    storage: LaneStorageProfile,
    governance: Option<String>,
    manifest_path: Option<PathBuf>,
    governance_rules: Option<GovernanceRules>,
    privacy_commitments: Vec<LanePrivacyCommitment>,
}
impl LaneManifestStatusBuilder {
    fn new(
        lane: LaneId,
        alias: String,
        dataspace: DataSpaceId,
        visibility: LaneVisibility,
        storage: LaneStorageProfile,
    ) -> Self {
        Self {
            lane,
            alias,
            dataspace,
            visibility,
            storage,
            governance: None,
            manifest_path: None,
            governance_rules: None,
            privacy_commitments: Vec::new(),
        }
    }
    fn governance(mut self, governance: Option<String>) -> Self {
        self.governance = governance;
        self
    }
    fn manifest_path(mut self, path: Option<PathBuf>) -> Self {
        self.manifest_path = path;
        self
    }
    fn governance_rules(mut self, rules: GovernanceRules) -> Self {
        self.governance_rules = Some(rules);
        self
    }
    fn privacy_commitments(mut self, commitments: Vec<LanePrivacyCommitment>) -> Self {
        self.privacy_commitments = commitments;
        self
    }
    fn build_ready(self) -> Result<LaneManifestStatus, LaneManifestBuilderError> {
        let Some(rules) = self.governance_rules else {
            return Err(LaneManifestBuilderError::MissingGovernanceRules);
        };
        Ok(LaneManifestStatus {
            lane: self.lane,
            alias: self.alias,
            dataspace: self.dataspace,
            visibility: self.visibility,
            storage: self.storage,
            governance: self.governance,
            manifest_path: self.manifest_path,
            governance_rules: Some(rules),
            privacy_commitments: self.privacy_commitments,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaneManifestBuilderError {
    MissingGovernanceRules,
}
impl fmt::Display for LaneManifestBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingGovernanceRules => write!(f, "governance rules not provided"),
        }
    }
}
impl std::error::Error for LaneManifestBuilderError {}
/// Governance rule set derived from a manifest file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GovernanceRules {
    /// Semantic version of the manifest (major).
    pub version: u32,
    /// Committee members / validators configured for the lane.
    pub validators: Vec<AccountId>,
    /// Explicit validator-account to peer-id bindings configured for the lane.
    pub validator_bindings: Vec<ManifestValidatorBinding>,
    /// Quorum threshold applied to the validator set.
    pub quorum: Option<u32>,
    /// Protected namespaces enforced by the lane governance module.
    pub protected_namespaces: BTreeSet<Name>,
    /// Typed governance hooks with optional raw values for unknown entries.
    pub hooks: GovernanceHooks,
}
#[derive(Debug, PartialEq, Eq)]
struct DataspaceManifestAuthority {
    validators: Vec<AccountId>,
    validator_bindings: Vec<(AccountId, PeerId)>,
    quorum: Option<u32>,
}

impl DataspaceManifestAuthority {
    fn from_rules(rules: &GovernanceRules) -> Option<Self> {
        if rules.validators.is_empty() {
            return None;
        }

        let mut validators = rules.validators.clone();
        validators.sort();
        let mut validator_bindings = rules
            .validator_bindings
            .iter()
            .map(|binding| (binding.validator.clone(), binding.peer_id.clone()))
            .collect::<Vec<_>>();
        validator_bindings.sort();

        Some(Self {
            validators,
            validator_bindings,
            quorum: rules.quorum,
        })
    }
}
/// Explicit validator binding declared in an admin-managed lane manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManifestValidatorBinding {
    /// Validator authority account.
    pub validator: AccountId,
    /// Consensus and routed-traffic peer identity.
    pub peer_id: PeerId,
    /// Optional Torii base URL used when authoritative routing must bridge over HTTP.
    pub torii_url: Option<String>,
}
/// Artifacts derived from a manifest file.
#[derive(Debug, Clone)]
struct ManifestArtifacts {
    rules: GovernanceRules,
    privacy_commitments: Vec<LanePrivacyCommitment>,
}
/// Parsed governance hook policies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GovernanceHooks {
    /// Runtime upgrade admission policy.
    pub runtime_upgrade: Option<RuntimeUpgradeHook>,
}
/// Runtime upgrade governance hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeUpgradeHook {
    /// Whether runtime-upgrade instructions are allowed.
    pub allow: bool,
    /// Require metadata to accompany runtime-upgrade transactions.
    pub require_metadata: bool,
    /// Metadata key enforced by this hook (defaults to `gov_upgrade_id` when `require_metadata` or
    /// `allowed_ids` are present).
    pub metadata_key: Option<Name>,
    /// Optional allowlist of metadata values (`String`).
    pub allowed_ids: Option<BTreeSet<String>>,
}
impl GovernanceHooks {
    fn from_manifest_hooks(hooks: Option<&BTreeMap<String, JsonValue>>) -> Result<Self, String> {
        let mut parsed = Self::default();
        if let Some(entries) = hooks {
            for (key, value) in entries {
                let trimmed = key.trim();
                if trimmed.is_empty() {
                    return Err("hook names cannot be blank".into());
                }
                match trimmed {
                    "runtime_upgrade" => {
                        let hook = RuntimeUpgradeHook::from_json(value).map_err(|err| {
                            format!("invalid runtime_upgrade hook configuration: {err}")
                        })?;
                        parsed.runtime_upgrade = Some(hook);
                    }
                    other => return Err(format!("unsupported governance hook `{other}`")),
                }
            }
        }
        Ok(parsed)
    }
}
impl RuntimeUpgradeHook {
    fn from_json(value: &JsonValue) -> Result<Self, String> {
        let JsonValue::Object(map) = value else {
            return Err("runtime_upgrade hook must be a JSON object".into());
        };
        for key in map.keys() {
            if !matches!(
                key.as_str(),
                "allow" | "require_metadata" | "metadata_key" | "allowed_ids"
            ) {
                return Err(format!("unsupported runtime_upgrade field `{key}`"));
            }
        }
        let mut allow = true;
        if let Some(entry) = map.get("allow") {
            match entry {
                JsonValue::Bool(flag) => allow = *flag,
                _ => return Err("runtime_upgrade.allow must be a boolean".into()),
            }
        }
        let mut require_metadata = false;
        if let Some(entry) = map.get("require_metadata") {
            match entry {
                JsonValue::Bool(flag) => require_metadata = *flag,
                _ => {
                    return Err("runtime_upgrade.require_metadata must be a boolean".into());
                }
            }
        }
        let mut metadata_key: Option<Name> = None;
        if let Some(entry) = map.get("metadata_key") {
            match entry {
                JsonValue::String(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        return Err("runtime_upgrade.metadata_key must not be blank".into());
                    }
                    metadata_key = Some(Name::from_str(trimmed).map_err(|err| {
                        format!("invalid runtime_upgrade.metadata_key `{trimmed}`: {err}")
                    })?);
                }
                _ => return Err("runtime_upgrade.metadata_key must be a string".into()),
            }
        }
        let mut allowed_ids: Option<BTreeSet<String>> = None;
        if let Some(entry) = map.get("allowed_ids") {
            match entry {
                JsonValue::Array(values) => {
                    let mut ids = BTreeSet::new();
                    for value in values {
                        match value {
                            JsonValue::String(raw) => {
                                let trimmed = raw.trim();
                                if trimmed.is_empty() {
                                    return Err(
                                        "runtime_upgrade.allowed_ids entries must not be blank"
                                            .into(),
                                    );
                                }
                                if !ids.insert(trimmed.to_string()) {
                                    return Err(
                                        "runtime_upgrade.allowed_ids entries must not duplicate values"
                                            .into(),
                                    );
                                }
                            }
                            _ => {
                                return Err(
                                    "runtime_upgrade.allowed_ids entries must be strings".into()
                                );
                            }
                        }
                    }
                    if !ids.is_empty() {
                        allowed_ids = Some(ids);
                    }
                }
                _ => return Err("runtime_upgrade.allowed_ids must be an array".into()),
            }
        }
        if (require_metadata || allowed_ids.is_some()) && metadata_key.is_none() {
            metadata_key = Some(Name::from_str("gov_upgrade_id").map_err(|err| {
                format!("failed to derive default runtime_upgrade metadata key: {err}")
            })?);
        }
        Ok(Self {
            allow,
            require_metadata,
            metadata_key,
            allowed_ids,
        })
    }
}
impl GovernanceRules {
    fn from_manifest(alias: &str, manifest: &NativeLaneManifestV1) -> Result<Self, String> {
        let version = manifest.version.unwrap_or(NativeLaneManifestV1::VERSION);
        if version != NativeLaneManifestV1::VERSION {
            return Err(format!(
                "manifest version {version} is not supported (expected 1)"
            ));
        }
        let mut validators = Vec::new();
        let mut validator_bindings = Vec::new();
        if let Some(entries) = manifest.validators.as_ref() {
            let mut seen_validators = BTreeSet::new();
            let mut seen_peer_ids = BTreeSet::new();
            for entry in entries {
                let validator_raw = entry
                    .validator
                    .as_deref()
                    .ok_or_else(|| "validator entry missing validator account".to_owned())?;
                let validator_trimmed = validator_raw.trim();
                if validator_trimmed.is_empty() {
                    return Err("validator entry cannot be blank".into());
                }
                let account = AccountId::parse_encoded(validator_trimmed)
                    .map_err(|err| format!("invalid validator id `{validator_trimmed}`: {err}"))?;
                if !seen_validators.insert(account.clone()) {
                    return Err(format!(
                        "duplicate validator id `{validator_trimmed}` in lane `{alias}`"
                    ));
                }
                let peer_raw = entry
                    .peer_id
                    .as_deref()
                    .ok_or_else(|| "validator entry missing peer_id".to_owned())?;
                let peer_trimmed = peer_raw.trim();
                if peer_trimmed.is_empty() {
                    return Err("validator peer_id cannot be blank".into());
                }
                let peer_id = PeerId::from_str(peer_trimmed)
                    .map_err(|err| format!("invalid validator peer_id `{peer_trimmed}`: {err}"))?;
                if !seen_peer_ids.insert(peer_id.clone()) {
                    return Err(format!(
                        "duplicate validator peer_id `{peer_trimmed}` in lane `{alias}`"
                    ));
                }
                let torii_url = entry
                    .torii_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
                let torii_url = match torii_url {
                    Some(url) => {
                        // Manifests are public consensus inputs. Do not admit URL
                        // credentials or repeat rejected values in diagnostics.
                        if url.contains('#') {
                            return Err("validator torii_url must not contain a fragment".into());
                        }
                        let uri = http::Uri::from_str(&url)
                            .map_err(|_| "invalid validator torii_url".to_owned())?;
                        if uri.scheme().is_none() || uri.authority().is_none() {
                            return Err(
                                "validator torii_url must include an absolute scheme and authority"
                                    .into(),
                            );
                        }
                        if uri
                            .authority()
                            .is_some_and(|authority| authority.as_str().contains('@'))
                            || uri.query().is_some()
                        {
                            return Err(
                                "validator torii_url must not contain user information or a query"
                                    .into(),
                            );
                        }
                        Some(url)
                    }
                    None => None,
                };
                validators.push(account.clone());
                validator_bindings.push(ManifestValidatorBinding {
                    validator: account,
                    peer_id,
                    torii_url,
                });
            }
        }
        let quorum = manifest.quorum;
        if let Some(q) = quorum {
            if q == 0 {
                return Err("validator quorum must be greater than zero".into());
            }
            if validators.is_empty() {
                return Err("validator quorum requires an explicit validator set".into());
            }
            if usize::try_from(q)
                .ok()
                .is_some_and(|q_usize| q_usize > validators.len())
            {
                return Err(format!(
                    "validator quorum {q} exceeds validator set size {} for lane `{alias}`",
                    validators.len()
                ));
            }
        }
        let mut protected_namespaces = BTreeSet::new();
        if let Some(namespaces) = manifest.protected_namespaces.as_ref() {
            for ns in namespaces {
                let trimmed = ns.trim();
                if trimmed.is_empty() {
                    return Err("protected namespace cannot be blank".into());
                }
                let name = Name::from_str(trimmed)
                    .map_err(|err| format!("invalid protected namespace `{trimmed}`: {err}"))?;
                if !protected_namespaces.insert(name) {
                    return Err(format!(
                        "duplicate protected namespace `{trimmed}` in lane `{alias}`"
                    ));
                }
            }
        }
        let hooks = GovernanceHooks::from_manifest_hooks(manifest.hooks.as_ref())?;
        Ok(Self {
            version,
            validators,
            validator_bindings,
            quorum,
            protected_namespaces,
            hooks,
        })
    }
}
mod authority;
mod runtime_overlay;
#[cfg(test)]
pub(crate) mod test_support;

/// Registry of manifests keyed by lane identifier.
#[derive(Debug)]
pub struct LaneManifestRegistry {
    statuses: BTreeMap<LaneId, LaneManifestStatus>,
    /// Immutable, parsed source snapshot used for deterministic catalog rebinding.
    ///
    /// Test/telemetry registries assembled from statuses do not have a filesystem
    /// source and use their existing alias-bound statuses as templates instead.
    source_snapshot: Option<Arc<LaneManifestSourceSnapshot>>,
    /// Original startup source authority, retained independently of committed additions.
    baseline_source_snapshot: Option<Arc<LaneManifestSourceSnapshot>>,
    /// Exact effective catalog used for the current source binding, independent of source digest.
    bound_catalog_hash: Option<Hash>,
    /// Every manifest alias accepted for the immutable active-catalog source set.
    manifest_source_aliases: BTreeSet<String>,
    /// Digest of the effective active-catalog manifest source set.
    consensus_policy_digest: [u8; 32],
}
impl Default for LaneManifestRegistry {
    fn default() -> Self {
        let source_snapshot = Arc::new(LaneManifestSourceSnapshot::empty());
        Self {
            statuses: BTreeMap::new(),
            manifest_source_aliases: BTreeSet::new(),
            consensus_policy_digest: source_snapshot.consensus_policy_digest(),
            source_snapshot: Some(source_snapshot),
            baseline_source_snapshot: None,
            bound_catalog_hash: None,
        }
    }
}
/// Deferred source locations or immutable parsed inputs from one bounded scan.
///
/// The first bind materializes only active aliases. Catalog lifecycle rebinding then consumes the
/// materialized snapshot and never reopens a path, so a post-startup file replacement cannot change
/// admission semantics outside the explicit, digest-checked hot-reload path.
#[derive(Debug, Clone)]
pub struct LaneManifestSourceSnapshot {
    manifests_by_alias: BTreeMap<String, FrozenLaneManifestSource>,
    /// Startup catalog identity, excluded from the existing frozen-source digest.
    bound_lanes: BTreeMap<LaneId, LaneConfig>,
    governance_overlay: Option<FrozenGovernanceOverlaySource>,
    consensus_policy_digest: [u8; 32],
    /// Deferred source configuration, consumed exactly once when the active lane catalog is known.
    pending_registry: Option<LaneRegistry>,
}
#[derive(Debug, Clone)]
struct FrozenLaneManifestSource {
    /// Absent for a manifest published through authenticated world state.
    path: Option<PathBuf>,
    parsed: Result<NativeLaneManifestV1, String>,
    content_digest: LaneManifestSourceContentDigestV1,
}
#[derive(Debug, Clone)]
struct FrozenGovernanceOverlaySource {
    path: PathBuf,
    parsed: Result<GovernanceCatalogFile, String>,
    content_digest: LaneManifestSourceContentDigestV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::LaneManifestSourceSetDigestV1")]
#[derive(Encode)]
struct LaneManifestSourceSetDigestV1 {
    version: u8,
    manifests: Vec<LaneManifestSourceDigestV1>,
    governance_overlay: Option<LaneManifestSourceContentDigestV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::LaneManifestSourceDigestV1")]
#[derive(Encode)]
struct LaneManifestSourceDigestV1 {
    alias: String,
    content: LaneManifestSourceContentDigestV1,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::LaneManifestSourceContentDigestV1")]
#[derive(Debug, Clone, Encode)]
struct LaneManifestSourceContentDigestV1 {
    valid: bool,
    digest: [u8; 32],
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::LaneManifestRegistryDigestV1")]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
#[derive(Encode)]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
struct LaneManifestRegistryDigestV1 {
    version: u8,
    lanes: Vec<LaneManifestStatusDigestV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::LaneManifestStatusDigestV1")]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
#[derive(Encode)]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
struct LaneManifestStatusDigestV1 {
    lane: u32,
    alias: String,
    dataspace: u64,
    visibility: u8,
    storage: u8,
    governance: Option<String>,
    ready: bool,
    rules: Option<GovernanceRulesDigestV1>,
    privacy_commitments: Vec<LanePrivacyCommitmentDigestV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::GovernanceRulesDigestV1")]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
#[derive(Encode)]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
struct GovernanceRulesDigestV1 {
    version: u32,
    validators: Vec<AccountId>,
    validator_bindings: Vec<ManifestValidatorBindingDigestV1>,
    quorum: Option<u32>,
    protected_namespaces: Vec<Name>,
    runtime_upgrade: Option<RuntimeUpgradeHookDigestV1>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::ManifestValidatorBindingDigestV1")]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
#[derive(Encode)]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
struct ManifestValidatorBindingDigestV1 {
    validator: AccountId,
    peer_id: PeerId,
    torii_url: Option<String>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::RuntimeUpgradeHookDigestV1")]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
#[derive(Encode)]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
struct RuntimeUpgradeHookDigestV1 {
    allow: bool,
    require_metadata: bool,
    metadata_key: Option<Name>,
    allowed_ids: Option<Vec<String>>,
}
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::governance::manifest::LanePrivacyCommitmentDigestV1")]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
#[derive(Encode)]
#[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
enum LanePrivacyCommitmentDigestV1 {
    Merkle {
        id: u16,
        root: [u8; 32],
        max_depth: u8,
    },
}
impl LaneManifestSourceSnapshot {
    fn empty() -> Self {
        let mut snapshot = Self {
            manifests_by_alias: BTreeMap::new(),
            bound_lanes: BTreeMap::new(),
            governance_overlay: None,
            consensus_policy_digest: [0; 32],
            pending_registry: None,
        };
        snapshot.consensus_policy_digest = snapshot.compute_consensus_policy_digest();
        snapshot
    }
    /// Capture the configured source locations for one active-catalog binding.
    ///
    /// Filesystem materialization is deferred until [`Self::bind`] supplies the
    /// active lane aliases. This prevents unknown or future files in a manifest
    /// directory from consuming startup memory. The materialized snapshot is
    /// still immutable and never reopens files during catalog rebinding.
    #[must_use]
    pub fn load(registry_cfg: &LaneRegistry) -> Self {
        let mut snapshot = Self {
            manifests_by_alias: BTreeMap::new(),
            bound_lanes: BTreeMap::new(),
            governance_overlay: None,
            consensus_policy_digest: [0; 32],
            pending_registry: Some(registry_cfg.clone()),
        };
        snapshot.consensus_policy_digest = snapshot.compute_consensus_policy_digest();
        snapshot
    }
    fn load_for_catalog(registry_cfg: &LaneRegistry, lane_catalog: &LaneCatalog) -> Self {
        let active_aliases = lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.alias.as_str())
            .collect::<BTreeSet<_>>();
        let manifest_dir = registry_cfg.manifest_directory.as_deref();
        let cache_dir = registry_cfg.cache_directory.as_deref();
        let source_paths = LaneManifestRegistry::collect_manifest_sources(
            manifest_dir,
            cache_dir,
            &active_aliases,
        );
        let mut budget = ManifestSourceLoadBudget::default();
        // The overlay is applied before lane sources and therefore consumes the
        // aggregate startup budget first, independent of directory iteration order.
        let governance_overlay = cache_dir
            .and_then(LaneManifestRegistry::governance_overlay_path)
            .map(|path| LaneManifestRegistry::freeze_governance_overlay_source(path, &mut budget));
        let manifests_by_alias = source_paths
            .into_iter()
            .map(|(alias, path)| {
                let source = LaneManifestRegistry::freeze_manifest_source(path, &mut budget);
                (alias, source)
            })
            .collect();
        let mut snapshot = Self {
            manifests_by_alias,
            bound_lanes: lane_catalog
                .lanes()
                .iter()
                .map(|lane| (lane.id, lane.clone()))
                .collect(),
            governance_overlay,
            consensus_policy_digest: [0; 32],
            pending_registry: None,
        };
        snapshot.consensus_policy_digest = snapshot.compute_consensus_policy_digest();
        snapshot
    }
    /// Bind this immutable source set to an active catalog.
    #[must_use]
    pub fn bind(
        self: &Arc<Self>,
        lane_catalog: &LaneCatalog,
        governance_catalog: &GovernanceCatalog,
    ) -> LaneManifestRegistry {
        LaneManifestRegistry::from_source_snapshot(
            Arc::clone(self),
            lane_catalog,
            governance_catalog,
        )
    }
    /// Canonical digest of this materialized active-catalog source snapshot.
    #[must_use]
    pub const fn consensus_policy_digest(&self) -> [u8; 32] {
        self.consensus_policy_digest
    }
    fn compute_consensus_policy_digest(&self) -> [u8; 32] {
        const DOMAIN: &[u8] = b"iroha:nexus:lane-manifest-source-set:v1\0";
        let manifests = self
            .manifests_by_alias
            .iter()
            .map(|(alias, source)| LaneManifestSourceDigestV1 {
                alias: alias.clone(),
                content: source.content_digest.clone(),
            })
            .collect();
        let encoded = LaneManifestSourceSetDigestV1 {
            version: 1,
            manifests,
            governance_overlay: self
                .governance_overlay
                .as_ref()
                .map(|source| source.content_digest.clone()),
        }
        .encode();
        Hash::new_from_chunks(&[DOMAIN, encoded.as_slice()]).into()
    }
    fn apply_governance_overlay(&self, catalog: &mut GovernanceCatalog) {
        let Some(source) = self.governance_overlay.as_ref() else {
            return;
        };
        let parsed = match source.parsed.as_ref() {
            Ok(parsed) => parsed,
            Err(reason) => {
                warn!(
                    path = %source.path.display(),
                    reason,
                    "frozen governance catalog overlay is invalid"
                );
                return;
            }
        };
        let mut applied = false;
        if let Some(default_module) = parsed.default_module.as_deref() {
            let trimmed = default_module.trim();
            if trimmed.is_empty() {
                warn!(
                    path = %source.path.display(),
                    "default_module entry in governance catalog overlay is blank; ignoring"
                );
            } else {
                catalog.default_module = Some(trimmed.to_owned());
                applied = true;
            }
        }
        for (name, module) in &parsed.modules {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                warn!(
                    path = %source.path.display(),
                    "governance catalog overlay encountered module with blank name; skipping"
                );
                continue;
            }
            catalog.modules.insert(
                trimmed.to_owned(),
                ConfigGovernanceModule {
                    module_type: module.module_type.clone(),
                    params: module.params.clone(),
                },
            );
            applied = true;
        }
        if applied {
            info!(
                path = %source.path.display(),
                "applied frozen governance catalog overlay"
            );
        }
    }
}
impl LaneManifestRegistry {
    /// Construct an empty registry (no lanes require manifests).
    pub fn empty() -> Self {
        Self::default()
    }
    /// Construct the fail-closed empty registry used only during emergency Fast startup.
    ///
    /// Unlike an ordinary empty registry, this provisional value has no frozen
    /// source and cannot authorize a materialized State transition.
    pub fn provisional_empty_for_emergency_fast_startup() -> Self {
        let mut registry = Self::empty();
        registry.source_snapshot = None;
        registry
    }
    /// Return the canonical digest of the accepted active-catalog manifest source set.
    ///
    /// It binds each active lane source and the governance overlay while excluding
    /// their filesystem locations. Unknown and future lane files are intentionally
    /// outside the snapshot and cannot consume startup resources.
    #[must_use]
    pub fn consensus_policy_digest(&self) -> [u8; 32] {
        self.consensus_policy_digest
    }
    #[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
    fn status_policy_digest(statuses: &BTreeMap<LaneId, LaneManifestStatus>) -> [u8; 32] {
        const DOMAIN: &[u8] = b"iroha:nexus:lane-manifest-policy-set:v1\0";
        let lanes = statuses
            .values()
            .map(|status| {
                let rules = status.governance_rules.as_ref().map(|rules| {
                    let mut validators = rules.validators.clone();
                    validators.sort();
                    let mut bindings = rules.validator_bindings.clone();
                    bindings.sort();
                    let validator_bindings = bindings
                        .into_iter()
                        .map(|binding| ManifestValidatorBindingDigestV1 {
                            validator: binding.validator,
                            peer_id: binding.peer_id,
                            torii_url: binding.torii_url,
                        })
                        .collect();
                    let runtime_upgrade = rules.hooks.runtime_upgrade.as_ref().map(|hook| {
                        RuntimeUpgradeHookDigestV1 {
                            allow: hook.allow,
                            require_metadata: hook.require_metadata,
                            metadata_key: hook.metadata_key.clone(),
                            allowed_ids: hook
                                .allowed_ids
                                .as_ref()
                                .map(|ids| ids.iter().cloned().collect()),
                        }
                    });
                    GovernanceRulesDigestV1 {
                        version: rules.version,
                        validators,
                        validator_bindings,
                        quorum: rules.quorum,
                        protected_namespaces: rules.protected_namespaces.iter().cloned().collect(),
                        runtime_upgrade,
                    }
                });
                let mut privacy_commitments = status.privacy_commitments.clone();
                privacy_commitments.sort_unstable_by_key(LanePrivacyCommitment::id);
                let privacy_commitments = privacy_commitments
                    .into_iter()
                    .map(|commitment| match commitment.scheme() {
                        CommitmentScheme::Merkle(merkle) => LanePrivacyCommitmentDigestV1::Merkle {
                            id: commitment.id().get(),
                            root: *merkle.root().as_ref(),
                            max_depth: merkle.max_depth(),
                        },
                    })
                    .collect();
                LaneManifestStatusDigestV1 {
                    lane: status.lane.as_u32(),
                    alias: status.alias.clone(),
                    dataspace: status.dataspace.as_u64(),
                    visibility: match status.visibility {
                        LaneVisibility::Public => 0,
                        LaneVisibility::Restricted => 1,
                    },
                    storage: match status.storage {
                        LaneStorageProfile::FullReplica => 0,
                        LaneStorageProfile::CommitmentOnly => 1,
                        LaneStorageProfile::SplitReplica => 2,
                    },
                    governance: status.governance.clone(),
                    ready: status.manifest_path.is_some() && rules.is_some(),
                    rules,
                    privacy_commitments,
                }
            })
            .collect();
        let encoded = LaneManifestRegistryDigestV1 { version: 1, lanes }.encode();
        Hash::new_from_chunks(&[DOMAIN, encoded.as_slice()]).into()
    }
    fn freeze_manifest_source(
        path: PathBuf,
        budget: &mut ManifestSourceLoadBudget,
    ) -> FrozenLaneManifestSource {
        let read_limit = LANE_MANIFEST_MAX_BYTES_V1.min(budget.remaining_bytes());
        if read_limit == 0 {
            return Self::invalid_manifest_source(
                path,
                "active manifest aggregate source-byte budget is exhausted".to_owned(),
                b"manifest-source-aggregate-byte-limit",
            );
        }
        let raw = match Self::read_bounded_regular_file(&path, read_limit) {
            Ok(raw) => raw,
            Err(err) => {
                return Self::invalid_manifest_source(
                    path,
                    format!("unable to read bounded regular manifest file: {err}"),
                    b"unreadable-or-oversize-manifest-source",
                );
            }
        };
        let raw_digest: [u8; 32] = Hash::new(raw.as_slice()).into();
        if let Err(err) = budget.charge_bytes(raw.len()) {
            return Self::invalid_manifest_source_with_digest(path, err, raw_digest);
        }
        let parsed = match Self::parse_bounded_manifest_json(&raw, budget) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Self::invalid_manifest_source_with_digest(path, err, raw_digest);
            }
        };
        // Do not retain raw and canonical copies at the same time.
        drop(raw);
        if let Err(err) = Self::validate_manifest_source_bounds(&parsed) {
            return Self::invalid_manifest_source_with_digest(path, err, raw_digest);
        }
        let canonical = match json::to_json(&parsed) {
            Ok(canonical) => canonical,
            Err(err) => {
                return Self::invalid_manifest_source_with_digest(
                    path,
                    format!("manifest canonical JSON encode error: {err}"),
                    raw_digest,
                );
            }
        };
        if canonical.len() > LANE_MANIFEST_MAX_CANONICAL_BYTES_V1 {
            return Self::invalid_manifest_source_with_digest(
                path,
                format!(
                    "manifest canonical JSON bytes {} exceed first-release limit {LANE_MANIFEST_MAX_CANONICAL_BYTES_V1}",
                    canonical.len()
                ),
                raw_digest,
            );
        }
        let canonical_digest = Hash::new(canonical.as_bytes()).into();
        drop(canonical);
        FrozenLaneManifestSource {
            path: Some(path),
            parsed: Ok(parsed),
            content_digest: LaneManifestSourceContentDigestV1 {
                valid: true,
                digest: canonical_digest,
            },
        }
    }
    fn freeze_governance_overlay_source(
        path: PathBuf,
        budget: &mut ManifestSourceLoadBudget,
    ) -> FrozenGovernanceOverlaySource {
        let read_limit = GOVERNANCE_OVERLAY_MAX_BYTES_V1.min(budget.remaining_bytes());
        if read_limit == 0 {
            return Self::invalid_governance_overlay_source(
                path,
                "manifest aggregate source-byte budget is exhausted before overlay load".to_owned(),
                b"governance-overlay-aggregate-byte-limit",
            );
        }
        let raw = match Self::read_bounded_regular_file(&path, read_limit) {
            Ok(raw) => raw,
            Err(err) => {
                return Self::invalid_governance_overlay_source(
                    path,
                    format!("unable to read bounded regular governance overlay: {err}"),
                    b"unreadable-or-oversize-governance-overlay",
                );
            }
        };
        let raw_digest: [u8; 32] = Hash::new(raw.as_slice()).into();
        if let Err(err) = budget.charge_bytes(raw.len()) {
            return Self::invalid_governance_overlay_source_with_digest(path, err, raw_digest);
        }
        let parsed = match Self::parse_bounded_governance_overlay_json(&raw, budget) {
            Ok(parsed) => parsed,
            Err(err) => {
                return Self::invalid_governance_overlay_source_with_digest(path, err, raw_digest);
            }
        };
        drop(raw);
        if let Err(err) = Self::validate_governance_overlay_source_bounds(&parsed) {
            return Self::invalid_governance_overlay_source_with_digest(path, err, raw_digest);
        }
        let canonical = match json::to_json(&parsed) {
            Ok(canonical) => canonical,
            Err(err) => {
                return Self::invalid_governance_overlay_source_with_digest(
                    path,
                    format!("governance overlay canonical JSON encode error: {err}"),
                    raw_digest,
                );
            }
        };
        if canonical.len() > GOVERNANCE_OVERLAY_MAX_CANONICAL_BYTES_V1 {
            return Self::invalid_governance_overlay_source_with_digest(
                path,
                format!(
                    "governance overlay canonical JSON bytes {} exceed first-release limit {GOVERNANCE_OVERLAY_MAX_CANONICAL_BYTES_V1}",
                    canonical.len()
                ),
                raw_digest,
            );
        }
        let canonical_digest = Hash::new(canonical.as_bytes()).into();
        drop(canonical);
        FrozenGovernanceOverlaySource {
            path,
            parsed: Ok(parsed),
            content_digest: LaneManifestSourceContentDigestV1 {
                valid: true,
                digest: canonical_digest,
            },
        }
    }
    fn invalid_manifest_source(
        path: PathBuf,
        reason: String,
        digest_marker: &[u8],
    ) -> FrozenLaneManifestSource {
        Self::invalid_manifest_source_with_digest(path, reason, Hash::new(digest_marker).into())
    }
    fn invalid_manifest_source_with_digest(
        path: PathBuf,
        reason: String,
        digest: [u8; 32],
    ) -> FrozenLaneManifestSource {
        FrozenLaneManifestSource {
            path: Some(path),
            parsed: Err(reason),
            content_digest: LaneManifestSourceContentDigestV1 {
                valid: false,
                digest,
            },
        }
    }
    fn invalid_governance_overlay_source(
        path: PathBuf,
        reason: String,
        digest_marker: &[u8],
    ) -> FrozenGovernanceOverlaySource {
        Self::invalid_governance_overlay_source_with_digest(
            path,
            reason,
            Hash::new(digest_marker).into(),
        )
    }
    fn invalid_governance_overlay_source_with_digest(
        path: PathBuf,
        reason: String,
        digest: [u8; 32],
    ) -> FrozenGovernanceOverlaySource {
        FrozenGovernanceOverlaySource {
            path,
            parsed: Err(reason),
            content_digest: LaneManifestSourceContentDigestV1 {
                valid: false,
                digest,
            },
        }
    }
    fn parse_bounded_manifest_json(
        raw: &[u8],
        budget: &mut ManifestSourceLoadBudget,
    ) -> Result<NativeLaneManifestV1, String> {
        let raw = str::from_utf8(raw)
            .map_err(|err| format!("manifest source is not valid UTF-8: {err}"))?;
        let footprint = Self::preflight_manifest_json(raw.as_bytes(), MANIFEST_JSON_LIMITS_V1)?;
        budget.charge_json(footprint)?;
        json::from_json(raw).map_err(|err| format!("manifest JSON parse error: {err}"))
    }
    fn parse_bounded_governance_overlay_json(
        raw: &[u8],
        budget: &mut ManifestSourceLoadBudget,
    ) -> Result<GovernanceCatalogFile, String> {
        let raw = str::from_utf8(raw)
            .map_err(|err| format!("governance overlay is not valid UTF-8: {err}"))?;
        let footprint = Self::preflight_manifest_json(raw.as_bytes(), MANIFEST_JSON_LIMITS_V1)?;
        budget.charge_json(footprint)?;
        json::from_json(raw).map_err(|err| format!("governance overlay JSON parse error: {err}"))
    }
    fn preflight_manifest_json(
        raw: &[u8],
        limits: ManifestJsonLimits,
    ) -> Result<ManifestJsonFootprint, String> {
        let mut footprint = ManifestJsonFootprint::default();
        let mut depth = 0_usize;
        let mut in_string = false;
        let mut escaped = false;
        let mut current_string_bytes = 0_usize;
        let mut in_scalar = false;
        for byte in raw.iter().copied() {
            if in_string {
                if escaped {
                    current_string_bytes =
                        current_string_bytes.checked_add(1).ok_or_else(|| {
                            "lane-manifest JSON string-byte counter overflowed".to_owned()
                        })?;
                    escaped = false;
                } else {
                    match byte {
                        b'\\' => {
                            current_string_bytes =
                                current_string_bytes.checked_add(1).ok_or_else(|| {
                                    "lane-manifest JSON string-byte counter overflowed".to_owned()
                                })?;
                            escaped = true;
                        }
                        b'"' => {
                            in_string = false;
                            footprint.strings =
                                footprint.strings.checked_add(1).ok_or_else(|| {
                                    "lane-manifest JSON string counter overflowed".to_owned()
                                })?;
                            footprint.string_bytes = footprint
                                .string_bytes
                                .checked_add(current_string_bytes)
                                .ok_or_else(|| {
                                    "lane-manifest JSON cumulative string-byte counter overflowed"
                                        .to_owned()
                                })?;
                            Self::charge_manifest_rule_unit(&mut footprint.rule_units, limits)?;
                            if footprint.strings > limits.max_strings {
                                return Err(format!(
                                    "lane-manifest JSON string count {} exceeds first-release limit {}",
                                    footprint.strings, limits.max_strings
                                ));
                            }
                            if footprint.string_bytes > limits.max_total_string_bytes {
                                return Err(format!(
                                    "lane-manifest JSON string bytes {} exceed first-release limit {}",
                                    footprint.string_bytes, limits.max_total_string_bytes
                                ));
                            }
                            current_string_bytes = 0;
                        }
                        _ => {
                            current_string_bytes =
                                current_string_bytes.checked_add(1).ok_or_else(|| {
                                    "lane-manifest JSON string-byte counter overflowed".to_owned()
                                })?;
                        }
                    }
                }
                if current_string_bytes > limits.max_string_bytes {
                    return Err(format!(
                        "lane-manifest JSON string bytes {current_string_bytes} exceed first-release limit {}",
                        limits.max_string_bytes
                    ));
                }
                continue;
            }
            match byte {
                b'"' => {
                    in_string = true;
                    in_scalar = false;
                }
                b'{' | b'[' => {
                    depth = depth.checked_add(1).ok_or_else(|| {
                        "lane-manifest JSON nesting counter overflowed".to_owned()
                    })?;
                    if depth > limits.max_depth {
                        return Err(format!(
                            "lane-manifest JSON nesting depth {depth} exceeds first-release limit {}",
                            limits.max_depth
                        ));
                    }
                    Self::charge_manifest_rule_unit(&mut footprint.rule_units, limits)?;
                    in_scalar = false;
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or_else(|| {
                        "lane-manifest JSON closes a container before opening one".to_owned()
                    })?;
                    in_scalar = false;
                }
                b':' | b',' => {
                    Self::charge_manifest_rule_unit(&mut footprint.rule_units, limits)?;
                    in_scalar = false;
                }
                b' ' | b'\t' | b'\r' | b'\n' => in_scalar = false,
                _ if !in_scalar => {
                    Self::charge_manifest_rule_unit(&mut footprint.rule_units, limits)?;
                    in_scalar = true;
                }
                _ => {}
            }
        }
        if in_string || escaped {
            return Err("lane-manifest JSON contains an unterminated string".to_owned());
        }
        if depth != 0 {
            return Err("lane-manifest JSON contains an unterminated container".to_owned());
        }
        Ok(footprint)
    }
    fn charge_manifest_rule_unit(
        rule_units: &mut usize,
        limits: ManifestJsonLimits,
    ) -> Result<(), String> {
        *rule_units = rule_units
            .checked_add(1)
            .ok_or_else(|| "lane-manifest JSON rule-unit counter overflowed".to_owned())?;
        if *rule_units > limits.max_rule_units {
            return Err(format!(
                "lane-manifest JSON rule units {} exceed first-release limit {}",
                *rule_units, limits.max_rule_units
            ));
        }
        Ok(())
    }
    fn validate_manifest_source_bounds(manifest: &NativeLaneManifestV1) -> Result<(), String> {
        Self::validate_optional_source_string(
            "lane alias",
            manifest.lane.as_deref(),
            MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
        )?;
        Self::validate_optional_source_string(
            "governance module",
            manifest.governance.as_deref(),
            MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
        )?;
        if let Some(validators) = manifest.validators.as_ref() {
            Self::validate_source_collection_len(
                "validator bindings",
                validators.len(),
                LANE_MANIFEST_MAX_VALIDATORS_V1,
            )?;
            for binding in validators {
                Self::validate_optional_source_string(
                    "validator identity",
                    binding.validator.as_deref(),
                    MANIFEST_SOURCE_MAX_IDENTITY_BYTES_V1,
                )?;
                Self::validate_optional_source_string(
                    "validator peer identity",
                    binding.peer_id.as_deref(),
                    MANIFEST_SOURCE_MAX_IDENTITY_BYTES_V1,
                )?;
                Self::validate_optional_source_string(
                    "validator Torii URL",
                    binding.torii_url.as_deref(),
                    MANIFEST_SOURCE_MAX_VALUE_BYTES_V1,
                )?;
            }
        }
        if let Some(namespaces) = manifest.protected_namespaces.as_ref() {
            Self::validate_source_collection_len(
                "protected namespaces",
                namespaces.len(),
                LANE_MANIFEST_MAX_PROTECTED_NAMESPACES_V1,
            )?;
            for namespace in namespaces {
                Self::validate_source_string(
                    "protected namespace",
                    namespace,
                    MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
                )?;
            }
        }
        if let Some(hooks) = manifest.hooks.as_ref() {
            Self::validate_source_collection_len(
                "governance hooks",
                hooks.len(),
                LANE_MANIFEST_MAX_HOOKS_V1,
            )?;
            for hook in hooks.keys() {
                Self::validate_source_string(
                    "governance hook name",
                    hook,
                    MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
                )?;
            }
        }
        if let Some(commitments) = manifest.privacy_commitments.as_ref() {
            Self::validate_source_collection_len(
                "privacy commitments",
                commitments.len(),
                LANE_MANIFEST_MAX_PRIVACY_COMMITMENTS_V1,
            )?;
            for commitment in commitments {
                Self::validate_optional_source_string(
                    "privacy commitment scheme",
                    commitment.scheme.as_deref(),
                    MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
                )?;
                if let Some(merkle) = commitment.merkle.as_ref() {
                    Self::validate_optional_source_string(
                        "privacy commitment root",
                        merkle.root.as_deref(),
                        MANIFEST_SOURCE_MAX_IDENTITY_BYTES_V1,
                    )?;
                }
            }
        }
        Ok(())
    }
    fn validate_governance_overlay_source_bounds(
        overlay: &GovernanceCatalogFile,
    ) -> Result<(), String> {
        Self::validate_optional_source_string(
            "default governance module",
            overlay.default_module.as_deref(),
            MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
        )?;
        Self::validate_source_collection_len(
            "governance overlay modules",
            overlay.modules.len(),
            GOVERNANCE_OVERLAY_MAX_MODULES_V1,
        )?;
        let mut total_params = 0_usize;
        for (name, module) in &overlay.modules {
            Self::validate_source_string(
                "governance overlay module name",
                name,
                MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
            )?;
            Self::validate_optional_source_string(
                "governance overlay module type",
                module.module_type.as_deref(),
                MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
            )?;
            Self::validate_source_collection_len(
                "governance overlay module parameters",
                module.params.len(),
                GOVERNANCE_OVERLAY_MAX_PARAMS_PER_MODULE_V1,
            )?;
            total_params = total_params
                .checked_add(module.params.len())
                .ok_or_else(|| "governance overlay parameter counter overflowed".to_owned())?;
            for (key, value) in &module.params {
                Self::validate_source_string(
                    "governance overlay parameter name",
                    key,
                    MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1,
                )?;
                Self::validate_source_string(
                    "governance overlay parameter value",
                    value,
                    MANIFEST_SOURCE_MAX_VALUE_BYTES_V1,
                )?;
            }
        }
        Self::validate_source_collection_len(
            "governance overlay total parameters",
            total_params,
            GOVERNANCE_OVERLAY_MAX_PARAMS_V1,
        )
    }
    fn validate_optional_source_string(
        label: &str,
        value: Option<&str>,
        max_bytes: usize,
    ) -> Result<(), String> {
        value.map_or(Ok(()), |value| {
            Self::validate_source_string(label, value, max_bytes)
        })
    }
    fn validate_source_string(label: &str, value: &str, max_bytes: usize) -> Result<(), String> {
        if value.len() > max_bytes {
            return Err(format!(
                "{label} bytes {} exceed first-release limit {max_bytes}",
                value.len()
            ));
        }
        Ok(())
    }
    fn validate_source_collection_len(
        label: &str,
        actual: usize,
        maximum: usize,
    ) -> Result<(), String> {
        if actual > maximum {
            return Err(format!(
                "{label} count {actual} exceeds first-release limit {maximum}"
            ));
        }
        Ok(())
    }
    fn read_bounded_regular_file(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        let path_metadata = secure_file_metadata::from_path(path)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source must be a direct regular file, not a symlink or special file",
            ));
        }
        if path_metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "source metadata length {} exceeds bounded read limit {max_bytes}",
                    path_metadata.len()
                ),
            ));
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options.open(path)?;
        let opened_metadata = secure_file_metadata::from_file(&file)?;
        if !opened_metadata.file_type().is_file()
            || opened_metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "opened source is not a bounded regular file",
            ));
        }
        if !Self::manifest_file_metadata_matches(&path_metadata, &opened_metadata) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source changed identity while it was opened",
            ));
        }
        let capacity = usize::try_from(opened_metadata.len())
            .unwrap_or(max_bytes)
            .min(max_bytes)
            .saturating_add(1);
        let mut raw = Vec::with_capacity(capacity);
        let take_limit = u64::try_from(max_bytes)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        file.by_ref().take(take_limit).read_to_end(&mut raw)?;
        if raw.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("source exceeds bounded read limit {max_bytes}"),
            ));
        }
        let final_metadata = secure_file_metadata::from_file(&file)?;
        if !Self::manifest_file_metadata_matches(&opened_metadata, &final_metadata)
            || final_metadata.len() != u64::try_from(raw.len()).unwrap_or(u64::MAX)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source changed while it was being read",
            ));
        }
        Ok(raw)
    }
    #[cfg(unix)]
    fn manifest_file_metadata_matches(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        left.dev() == right.dev() && left.ino() == right.ino() && left.len() == right.len()
    }
    #[cfg(windows)]
    fn manifest_file_metadata_matches(left: &SecureMetadata, right: &SecureMetadata) -> bool {
        left.file_type().is_file()
            && right.file_type().is_file()
            && left.volume_serial_number().is_some()
            && left.file_index().is_some()
            && left.volume_serial_number() == right.volume_serial_number()
            && left.file_index() == right.file_index()
            && left.len() == right.len()
    }
    #[cfg(not(any(unix, windows)))]
    fn manifest_file_metadata_matches(_left: &SecureMetadata, _right: &SecureMetadata) -> bool {
        false
    }
    /// Build the registry from one frozen scan of the provided source configuration.
    pub fn from_config(
        lane_catalog: &LaneCatalog,
        governance_catalog: &GovernanceCatalog,
        registry_cfg: &LaneRegistry,
    ) -> Self {
        let source_snapshot = Arc::new(LaneManifestSourceSnapshot::load(registry_cfg));
        source_snapshot.bind(lane_catalog, governance_catalog)
    }
    /// Bind a frozen parsed source snapshot to an active lane catalog.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn from_source_snapshot(
        source_snapshot: Arc<LaneManifestSourceSnapshot>,
        lane_catalog: &LaneCatalog,
        governance_catalog: &GovernanceCatalog,
    ) -> Self {
        if let Some(registry_cfg) = source_snapshot.pending_registry.as_ref() {
            let materialized = Arc::new(LaneManifestSourceSnapshot::load_for_catalog(
                registry_cfg,
                lane_catalog,
            ));
            return Self::from_source_snapshot(materialized, lane_catalog, governance_catalog);
        }
        // An empty source authority also acquires its immutable catalog identity
        // on the first bind, without materializing any filesystem locations.
        let source_snapshot = if source_snapshot.bound_lanes.is_empty() {
            let mut bound_source = (*source_snapshot).clone();
            bound_source.bound_lanes = lane_catalog
                .lanes()
                .iter()
                .map(|lane| (lane.id, lane.clone()))
                .collect();
            Arc::new(bound_source)
        } else {
            source_snapshot
        };
        let mut statuses = BTreeMap::new();
        let mut effective_governance = governance_catalog.clone();
        source_snapshot.apply_governance_overlay(&mut effective_governance);
        let manifest_source_aliases = source_snapshot.manifests_by_alias.keys().cloned().collect();
        let consensus_policy_digest = source_snapshot.consensus_policy_digest();
        debug!(
            alias_count = source_snapshot.manifests_by_alias.len(),
            "binding frozen lane manifest aliases"
        );
        for lane in lane_catalog.lanes() {
            let alias = lane.alias.clone();
            let governance = lane.governance.clone();
            let dataspace = lane.dataspace_id;
            let visibility = lane.visibility;
            let storage = lane.storage;
            let manifest_source = source_snapshot.manifests_by_alias.get(&alias);
            let status = manifest_source.map_or_else(
                || {
                    LaneManifestStatus::missing(
                        lane.id,
                        alias.clone(),
                        dataspace,
                        visibility,
                        storage,
                        governance.clone(),
                    )
                },
                |source| match source
                    .parsed
                    .as_ref()
                    .map_err(Clone::clone)
                    .and_then(|parsed| {
                        Self::validate_parsed_manifest(
                            parsed,
                            lane.id,
                            &alias,
                            governance.as_deref(),
                            &effective_governance,
                        )
                    }) {
                    Ok(artifacts) => LaneManifestStatus::builder(
                        lane.id,
                        alias.clone(),
                        dataspace,
                        visibility,
                        storage,
                    )
                    .governance(governance.clone())
                    .manifest_path(source.path.clone())
                    .governance_rules(artifacts.rules)
                    .privacy_commitments(artifacts.privacy_commitments)
                    .build_ready()
                    .unwrap_or_else(|err| {
                        warn!(
                            lane = %alias,
                            path = ?source.path,
                            reason = %err,
                            "failed to finalize lane manifest status"
                        );
                        LaneManifestStatus::missing(
                            lane.id,
                            alias.clone(),
                            dataspace,
                            visibility,
                            storage,
                            governance.clone(),
                        )
                    }),
                    Err(msg) => {
                        warn!(lane = %alias, reason = %msg, "invalid lane manifest");
                        LaneManifestStatus::missing(
                            lane.id,
                            alias.clone(),
                            dataspace,
                            visibility,
                            storage,
                            governance.clone(),
                        )
                    }
                },
            );
            statuses.insert(lane.id, status);
        }
        // Log governance modules lacking manifest declarations.
        for status in statuses.values() {
            if status.governance.is_some() && status.governance_rules.is_none() {
                if let Some(gov) = status.governance.as_deref()
                    && !effective_governance.modules.contains_key(gov)
                {
                    warn!(
                        lane = %status.alias,
                        module = gov,
                        "lane references governance module not defined in catalog"
                    );
                }
                debug!(
                    lane = %status.alias,
                    "lane governance manifest missing; queue will reject transactions for this lane"
                );
            }
        }
        Self {
            statuses,
            manifest_source_aliases,
            consensus_policy_digest,
            source_snapshot: Some(source_snapshot),
            baseline_source_snapshot: None,
            bound_catalog_hash: Some(
                iroha_data_model::nexus::LaneLifecycleParameterV1::catalog_hash(lane_catalog),
            ),
        }
    }
    fn collect_manifest_sources(
        manifest_dir: Option<&Path>,
        cache_dir: Option<&Path>,
        active_aliases: &BTreeSet<&str>,
    ) -> BTreeMap<String, PathBuf> {
        let mut manifests = BTreeMap::new();
        let mut duplicate_aliases = BTreeSet::new();
        if let Some(dir) = manifest_dir {
            if dir.exists() {
                Self::ingest_manifest_directory(
                    dir,
                    active_aliases,
                    &mut manifests,
                    &mut duplicate_aliases,
                    false,
                );
            } else {
                warn!(
                    path = %dir.display(),
                    "lane manifest directory missing; all governance lanes will remain locked until manifests are installed"
                );
            }
        }
        if let Some(dir) = cache_dir {
            if dir.exists() {
                Self::ingest_manifest_directory(
                    dir,
                    active_aliases,
                    &mut manifests,
                    &mut duplicate_aliases,
                    true,
                );
            } else if manifest_dir.is_some() {
                debug!(
                    path = %dir.display(),
                    "lane manifest cache directory missing; continuing with primary directory entries"
                );
            }
        }
        manifests
    }
    fn ingest_manifest_directory(
        dir: &Path,
        active_aliases: &BTreeSet<&str>,
        manifests: &mut BTreeMap<String, PathBuf>,
        duplicate_aliases: &mut BTreeSet<String>,
        override_existing: bool,
    ) {
        match fs::read_dir(dir) {
            Ok(entries) => {
                let mut seen_in_directory = BTreeSet::new();
                let mut ignored_unknown_sources = 0_usize;
                for entry in entries.flatten() {
                    let file_name = entry.file_name();
                    if override_existing
                        && file_name.as_os_str() == OsStr::new("governance_catalog.json")
                    {
                        continue;
                    }
                    let Some(alias) = Self::manifest_alias_from_file_name(&file_name) else {
                        continue;
                    };
                    // Unknown and future files are rejected before path allocation,
                    // metadata work, reads, parsing, or canonicalization.
                    if !active_aliases.contains(&alias.as_str()) {
                        ignored_unknown_sources = ignored_unknown_sources.saturating_add(1);
                        continue;
                    }
                    if duplicate_aliases.contains(&alias) {
                        warn!(
                            lane = %alias,
                            directory = %dir.display(),
                            file = ?file_name,
                            "manifest alias already invalidated by duplicate source; skipping"
                        );
                        continue;
                    }
                    if !seen_in_directory.insert(alias.clone()) {
                        warn!(
                            lane = %alias,
                            directory = %dir.display(),
                            file = ?file_name,
                            "duplicate manifest alias in directory; invalidating alias"
                        );
                        manifests.remove(&alias);
                        duplicate_aliases.insert(alias);
                        continue;
                    }
                    let path = entry.path();
                    let is_direct_regular_file = entry
                        .file_type()
                        .is_ok_and(|file_type| file_type.is_file() && !file_type.is_symlink());
                    if !is_direct_regular_file {
                        warn!(
                            lane = %alias,
                            path = %path.display(),
                            "active lane manifest source is not a direct regular file; skipping"
                        );
                        manifests.remove(&alias);
                        duplicate_aliases.insert(alias);
                        continue;
                    }
                    if manifests.contains_key(&alias) {
                        if override_existing {
                            if let Some(prev) = manifests.get(&alias) {
                                info!(
                                    lane = %alias,
                                    new_path = %path.display(),
                                    old_path = %prev.display(),
                                    "cache manifest overrides existing lane manifest"
                                );
                            }
                        } else {
                            warn!(
                                lane = %alias,
                                path = %path.display(),
                                "duplicate manifest alias in primary directory; skipping"
                            );
                            continue;
                        }
                    }
                    manifests.insert(alias, path);
                }
                if ignored_unknown_sources != 0 {
                    debug!(
                        directory = %dir.display(),
                        ignored_unknown_sources,
                        "ignored lane manifest sources outside the active catalog"
                    );
                }
            }
            Err(err) => {
                warn!(
                    path = %dir.display(),
                    ?err,
                    "failed to read lane manifest directory"
                );
            }
        }
    }
    fn manifest_alias_from_file_name(file_name: &OsStr) -> Option<String> {
        let stem = file_name.to_str()?.strip_suffix(".json")?.trim();
        if stem.is_empty() {
            return None;
        }
        let alias = stem.strip_suffix(".manifest").unwrap_or(stem).trim();
        if alias.is_empty() || alias.len() > MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1 {
            return None;
        }
        Some(alias.to_string())
    }
    fn governance_overlay_path(cache_dir: &Path) -> Option<PathBuf> {
        let path = cache_dir.join("governance_catalog.json");
        match fs::symlink_metadata(&path) {
            Ok(_) => Some(path),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(_) => Some(path),
        }
    }
    #[allow(clippy::too_many_lines)]
    fn parse_privacy_commitments(
        alias: &str,
        manifest: &NativeLaneManifestV1,
    ) -> Result<Vec<LanePrivacyCommitment>, String> {
        let Some(entries) = manifest.privacy_commitments.as_ref() else {
            return Ok(Vec::new());
        };
        let mut commitments = Vec::new();
        let mut seen_ids = BTreeSet::new();
        for entry in entries {
            let id = entry.id.ok_or_else(|| {
                format!("privacy commitment entry missing `id` for lane `{alias}`")
            })?;
            if !seen_ids.insert(id) {
                return Err(format!(
                    "privacy commitment id {id} appears multiple times for lane `{alias}`"
                ));
            }
            let scheme_raw = entry.scheme.as_deref().ok_or_else(|| {
                format!("privacy commitment {id} is missing `scheme` for lane `{alias}`")
            })?;
            let scheme = scheme_raw.trim().to_ascii_lowercase();
            match scheme.as_str() {
                "merkle" => {
                    let merkle = entry.merkle.as_ref().ok_or_else(|| {
                    format!(
                        "privacy commitment {id} for lane `{alias}` must include a `merkle` section"
                    )
                })?;
                    let root_raw = merkle.root.as_deref().ok_or_else(|| {
                        format!(
                            "privacy commitment {id} for lane `{alias}` is missing `merkle.root`"
                        )
                    })?;
                    let max_depth = merkle.max_depth.ok_or_else(|| {
                    format!(
                        "privacy commitment {id} for lane `{alias}` is missing `merkle.max_depth`"
                    )
                })?;
                    if max_depth == 0 {
                        return Err(format!(
                            "privacy commitment {id} for lane `{alias}` has invalid `merkle.max_depth` (must be > 0)"
                        ));
                    }
                    let root_bytes =
                        Self::parse_hex_digest(alias, id, "merkle.root", root_raw.trim())?;
                    commitments.push(LanePrivacyCommitment::merkle(
                        LaneCommitmentId::new(id),
                        MerkleCommitment::from_root_bytes(root_bytes, max_depth),
                    ));
                }
                other => {
                    return Err(format!(
                        "privacy commitment {id} for lane `{alias}` uses unsupported scheme `{other}`; only `merkle` is accepted until an on-chain verifying-key-backed proof verifier is available"
                    ));
                }
            }
        }
        Ok(commitments)
    }
    fn parse_hex_digest(
        alias: &str,
        commitment_id: u16,
        field: &str,
        raw: &str,
    ) -> Result<[u8; 32], String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "privacy commitment {commitment_id} for lane `{alias}` has blank `{field}`"
            ));
        }
        let normalized = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if normalized.len() != 64 {
            return Err(format!(
                "privacy commitment {commitment_id} for lane `{alias}` must encode `{field}` as a 32-byte hex digest"
            ));
        }
        let bytes = decode(normalized).map_err(|err| {
            format!(
                "privacy commitment {commitment_id} for lane `{alias}` has invalid `{field}`: {err}"
            )
        })?;
        if bytes.len() != 32 {
            return Err(format!(
                "privacy commitment {commitment_id} for lane `{alias}` `{field}` decoded to {} bytes (expected 32)",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
    #[cfg(test)]
    fn validate_manifest(
        path: &Path,
        lane_id: LaneId,
        alias: &str,
        lane_governance: Option<&str>,
        catalog: &GovernanceCatalog,
    ) -> Result<ManifestArtifacts, String> {
        let mut budget = ManifestSourceLoadBudget::default();
        let source = Self::freeze_manifest_source(path.to_path_buf(), &mut budget);
        let parsed = source.parsed?;
        Self::validate_parsed_manifest(&parsed, lane_id, alias, lane_governance, catalog)
    }
    fn validate_parsed_manifest(
        parsed: &NativeLaneManifestV1,
        lane_id: LaneId,
        alias: &str,
        lane_governance: Option<&str>,
        catalog: &GovernanceCatalog,
    ) -> Result<ManifestArtifacts, String> {
        if let Some(manifest_lane) = parsed.lane.as_deref()
            && manifest_lane != alias
        {
            return Err(format!(
                "manifest targets lane \"{manifest_lane}\" but is located at alias \"{alias}\""
            ));
        }
        let manifest_governance = parsed.governance.as_deref();
        if let Some(expected) = lane_governance {
            match manifest_governance {
                Some(manifest_module) => {
                    if manifest_module != expected {
                        return Err(format!(
                            "manifest governance module {manifest_module} does not match lane configuration {expected}"
                        ));
                    }
                    if !catalog.modules.contains_key(expected) {
                        return Err(format!(
                            "lane references governance module `{expected}` not present in catalog"
                        ));
                    }
                }
                None => return Err("manifest missing governance module identifier".into()),
            }
        }
        let privacy_commitments = Self::parse_privacy_commitments(alias, parsed)?;
        let rules = GovernanceRules::from_manifest(alias, parsed)?;
        debug!(
            lane = alias,
            lane_id = lane_id.as_u32(),
            "bound frozen governance manifest"
        );
        Ok(ManifestArtifacts {
            rules,
            privacy_commitments,
        })
    }
    /// Install manifests into the registry from pre-built statuses (testing/telemetry scaffolding).
    #[cfg(any(test, feature = "telemetry", feature = "iroha-core-tests"))]
    pub fn from_statuses(statuses: BTreeMap<LaneId, LaneManifestStatus>) -> Self {
        let consensus_policy_digest = Self::status_policy_digest(&statuses);
        let manifest_source_aliases = statuses
            .values()
            .filter(|status| status.manifest_path.is_some())
            .map(|status| status.alias.clone())
            .collect();
        Self {
            statuses,
            manifest_source_aliases,
            consensus_policy_digest,
            source_snapshot: None,
            baseline_source_snapshot: None,
            bound_catalog_hash: None,
        }
    }
    /// Deterministically bind the installed immutable sources to a new catalog.
    ///
    /// This operation performs no filesystem access and preserves the source-set
    /// digest. Status-only test registries reuse alias-matched parsed artifacts.
    #[must_use]
    pub fn rebind(
        &self,
        lane_catalog: &LaneCatalog,
        governance_catalog: &GovernanceCatalog,
    ) -> Self {
        if let Some(source_snapshot) = self.source_snapshot.as_ref() {
            let mut rebound = source_snapshot.bind(lane_catalog, governance_catalog);
            rebound
                .baseline_source_snapshot
                .clone_from(&self.baseline_source_snapshot);
            return rebound;
        }
        let templates = self
            .statuses
            .values()
            .map(|status| (status.alias.as_str(), status))
            .collect::<BTreeMap<_, _>>();
        let statuses = lane_catalog
            .lanes()
            .iter()
            .map(|lane| {
                let status = templates.get(lane.alias.as_str()).map_or_else(
                    || {
                        LaneManifestStatus::missing(
                            lane.id,
                            lane.alias.clone(),
                            lane.dataspace_id,
                            lane.visibility,
                            lane.storage,
                            lane.governance.clone(),
                        )
                    },
                    |template| {
                        let mut rebound = (*template).clone();
                        rebound.lane = lane.id;
                        rebound.dataspace = lane.dataspace_id;
                        rebound.visibility = lane.visibility;
                        rebound.storage = lane.storage;
                        if rebound.governance != lane.governance {
                            return LaneManifestStatus::missing(
                                lane.id,
                                lane.alias.clone(),
                                lane.dataspace_id,
                                lane.visibility,
                                lane.storage,
                                lane.governance.clone(),
                            );
                        }
                        rebound
                    },
                );
                (lane.id, status)
            })
            .collect();
        Self {
            statuses,
            manifest_source_aliases: self.manifest_source_aliases.clone(),
            consensus_policy_digest: self.consensus_policy_digest,
            source_snapshot: None,
            baseline_source_snapshot: None,
            bound_catalog_hash: None,
        }
    }
    /// Whether the lane is ready for traffic under its governance manifest.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceGuardError`] when the lane is unknown or its
    /// governed/private semantics are unavailable.
    pub fn ensure_lane_ready(&self, lane_id: LaneId) -> Result<(), GovernanceGuardError> {
        let Some(status) = self.statuses.get(&lane_id) else {
            return Err(GovernanceGuardError::unknown_lane(lane_id));
        };
        if status.governance.is_some()
            && (!self.has_manifest(lane_id) || status.governance_rules.is_none())
        {
            return Err(GovernanceGuardError::missing_manifest(status));
        }
        if matches!(
            status.storage,
            LaneStorageProfile::CommitmentOnly | LaneStorageProfile::SplitReplica
        ) && (!self.has_manifest(lane_id) || status.privacy_commitments.is_empty())
        {
            return Err(GovernanceGuardError::missing_privacy_commitments(status));
        }
        Ok(())
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Validate that every active lane can enforce all configured manifest semantics.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceGuardError`] for an unknown lane, an active
    /// governed/private lane without a valid frozen source binding, or
    /// conflicting roster-bearing manifests in one physical dataspace.
    pub fn validate_active_coverage(&self) -> Result<(), GovernanceGuardError> {
        for lane_id in self.statuses.keys().copied() {
            self.ensure_lane_ready(lane_id)?;
        }
        let mut checked_dataspaces = BTreeSet::new();
        for status in self.statuses.values() {
            if checked_dataspaces.insert(status.dataspace) {
                self.dataspace_authority_rules(status.lane, status.dataspace)?;
            }
        }
        Ok(())
    }

    /// Validate active manifest coverage using the catalog's authority boundaries.
    ///
    /// Static lanes share manifest authority with other static lanes in the same
    /// physical dataspace. Autoscale-managed lanes carry an immutable, lane-local
    /// committee and are therefore validated independently, even when they use the
    /// same physical dataspace as a static lane.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceGuardError`] when a catalog lane is unknown, cannot
    /// enforce its configured manifest semantics, or conflicts with another
    /// static lane's manifest authority in the same dataspace.
    pub fn validate_active_coverage_for_catalog(
        &self,
        lane_catalog: &LaneCatalog,
    ) -> Result<(), GovernanceGuardError> {
        let mut static_lanes_by_dataspace = BTreeMap::<DataSpaceId, BTreeSet<LaneId>>::new();

        for lane in lane_catalog.lanes() {
            self.ensure_lane_ready(lane.id)?;
            if lane_uses_reserved_autoscale_metadata(lane) {
                self.dataspace_authority_rules_for_lanes(
                    lane.id,
                    lane.dataspace_id,
                    &BTreeSet::from([lane.id]),
                )?;
            } else {
                static_lanes_by_dataspace
                    .entry(lane.dataspace_id)
                    .or_default()
                    .insert(lane.id);
            }
        }

        for (dataspace_id, lanes) in static_lanes_by_dataspace {
            let target_lane = *lanes
                .first()
                .expect("static dataspace group must contain at least one lane");
            self.dataspace_authority_rules_for_lanes(target_lane, dataspace_id, &lanes)?;
        }

        Ok(())
    }
    /// Enumerate lanes missing manifests (for logging or tests).
    pub fn missing_entries(&self) -> Vec<&LaneManifestStatus> {
        self.statuses
            .values()
            .filter(|status| self.ensure_lane_ready(status.lane).is_err())
            .collect()
    }
    /// Collect lane aliases that currently lack manifests.
    pub fn missing_aliases(&self) -> BTreeSet<String> {
        self.missing_entries()
            .iter()
            .map(|status| status.alias.clone())
            .collect()
    }
    /// Retrieve the manifest status for `lane_id`, if available.
    pub fn status(&self, lane_id: LaneId) -> Option<&LaneManifestStatus> {
        self.statuses.get(&lane_id)
    }
    /// Return whether the frozen active-catalog source set contains `alias`.
    #[must_use]
    pub fn has_manifest_source_alias(&self, alias: &str) -> bool {
        self.manifest_source_aliases.contains(alias)
    }
    /// Retrieve parsed governance rules for `lane_id`, if available.
    pub fn lane_rules(&self, lane_id: LaneId) -> Option<&GovernanceRules> {
        self.status(lane_id).and_then(LaneManifestStatus::rules)
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Resolve the validator pool declared for a lane's physical dataspace.
    ///
    /// Policy-only manifests do not declare authority and are skipped. Every roster-bearing
    /// manifest in one dataspace must describe the same validator accounts, account-to-peer
    /// bindings, and quorum. Binding URLs and lane-local governance policy are deliberately not
    /// part of this consistency check.
    pub(crate) fn dataspace_authority_rules(
        &self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
    ) -> Result<Option<&GovernanceRules>, GovernanceGuardError> {
        self.dataspace_authority_rules_inner(lane_id, dataspace_id, None)
    }

    pub(crate) fn dataspace_authority_rules_for_lanes(
        &self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        eligible_lanes: &BTreeSet<LaneId>,
    ) -> Result<Option<&GovernanceRules>, GovernanceGuardError> {
        self.dataspace_authority_rules_inner(lane_id, dataspace_id, Some(eligible_lanes))
    }

    fn dataspace_authority_rules_inner(
        &self,
        lane_id: LaneId,
        dataspace_id: DataSpaceId,
        eligible_lanes: Option<&BTreeSet<LaneId>>,
    ) -> Result<Option<&GovernanceRules>, GovernanceGuardError> {
        let target_status = self.status(lane_id);
        if target_status.is_some_and(|status| status.dataspace != dataspace_id) {
            return Err(GovernanceGuardError::unknown_lane(lane_id));
        }
        if let Some(eligible_lanes) = eligible_lanes {
            for eligible_lane in eligible_lanes {
                if let Some(status) = self.status(*eligible_lane) {
                    self.ensure_lane_ready(*eligible_lane)?;
                    if status.dataspace != dataspace_id {
                        return Err(GovernanceGuardError::unknown_lane(*eligible_lane));
                    }
                }
            }
        }

        let mut authority_fingerprint = None;
        let mut fallback_rules = None;
        let mut target_rules = None;
        for status in self
            .statuses
            .values()
            .filter(|status| status.dataspace == dataspace_id)
            .filter(|status| {
                eligible_lanes.is_none_or(|eligible_lanes| eligible_lanes.contains(&status.lane))
            })
        {
            let Some(rules) = status.rules() else {
                continue;
            };
            let Some(fingerprint) = DataspaceManifestAuthority::from_rules(rules) else {
                continue;
            };
            if let Some(expected) = authority_fingerprint.as_ref()
                && expected != &fingerprint
            {
                return Err(GovernanceGuardError::dataspace_authority_conflict(
                    lane_id,
                    target_status,
                ));
            }
            if authority_fingerprint.is_none() {
                authority_fingerprint = Some(fingerprint);
                fallback_rules = Some(rules);
            }
            if status.lane == lane_id {
                target_rules = Some(rules);
            }
        }

        Ok(target_rules.or(fallback_rules))
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Retrieve the validator set declared for `lane_id`, if present.
    pub fn lane_validators(&self, lane_id: LaneId) -> Option<Vec<AccountId>> {
        self.lane_rules(lane_id)
            .map(|rules| rules.validators.clone())
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Retrieve explicit validator-account to peer-id bindings declared for `lane_id`, if present.
    pub fn lane_validator_bindings(
        &self,
        lane_id: LaneId,
    ) -> Option<Vec<ManifestValidatorBinding>> {
        self.lane_rules(lane_id)
            .map(|rules| rules.validator_bindings.clone())
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Retrieve the quorum declared for `lane_id`, if present.
    pub fn lane_quorum(&self, lane_id: LaneId) -> Option<u32> {
        self.lane_rules(lane_id).and_then(|rules| rules.quorum)
    }
    /// Snapshot the current manifest statuses for all lanes.
    #[must_use]
    pub fn statuses(&self) -> Vec<LaneManifestStatus> {
        self.statuses.values().cloned().collect()
    }
}
/// Whether `lane` carries metadata keys reserved for autoscaled lane lifecycle management.
pub(crate) fn lane_uses_reserved_autoscale_metadata(lane: &LaneConfig) -> bool {
    lane.metadata.contains_key(AUTOSCALE_META_MANAGED)
        || lane.metadata.contains_key(AUTOSCALE_META_CREATED_HEIGHT)
        || lane.metadata.contains_key(AUTOSCALE_META_DRAIN_STATE)
        || lane.metadata.contains_key(AUTOSCALE_META_COMMITTEE)
}
/// Governance guard error returned when a lane lacks an active manifest.
#[derive(Debug, Clone)]
pub struct GovernanceGuardError {
    /// Lane identifier.
    pub lane: LaneId,
    /// Human-readable alias.
    pub alias: String,
    /// Governance module configured in the catalog.
    pub governance: Option<String>,
    /// Reason why the lane is not ready for traffic.
    pub reason: GovernanceGuardReason,
}
impl GovernanceGuardError {
    /// Render the failure reason for logs.
    #[must_use]
    pub fn message(&self) -> String {
        match self.reason {
            GovernanceGuardReason::UnknownLane => format!(
                "lane {} is absent from the installed manifest registry snapshot",
                self.lane.as_u32(),
            ),
            GovernanceGuardReason::MissingManifest => self
                .governance
                .as_deref()
                .map_or_else(
                    || {
                        format!(
                            "lane \"{}\" ({}) requires a governance manifest but none was loaded",
                            self.alias,
                            self.lane.as_u32(),
                        )
                    },
                    |module| {
                        format!(
                            "lane \"{}\" ({}) references governance module \"{module}\" but no manifest was loaded",
                            self.alias,
                            self.lane.as_u32(),
                        )
                    },
                ),
            GovernanceGuardReason::MissingPrivacyCommitments => format!(
                "lane \"{}\" ({}) is configured for commitment-only storage but the manifest does not declare any privacy commitments",
                self.alias,
                self.lane.as_u32(),
            ),
            GovernanceGuardReason::DataspaceAuthorityConflict => format!(
                "lane \"{}\" ({}) shares a dataspace with conflicting manifest validator pools",
                self.alias,
                self.lane.as_u32(),
            ),
        }
    }
    /// Retrieve the guard failure reason.
    #[must_use]
    pub const fn reason(&self) -> GovernanceGuardReason {
        self.reason
    }
    fn missing_manifest(status: &LaneManifestStatus) -> Self {
        Self {
            lane: status.lane,
            alias: status.alias.clone(),
            governance: status.governance.clone(),
            reason: GovernanceGuardReason::MissingManifest,
        }
    }
    fn unknown_lane(lane: LaneId) -> Self {
        Self {
            lane,
            alias: format!("lane-{}", lane.as_u32()),
            governance: None,
            reason: GovernanceGuardReason::UnknownLane,
        }
    }
    fn missing_privacy_commitments(status: &LaneManifestStatus) -> Self {
        Self {
            lane: status.lane,
            alias: status.alias.clone(),
            governance: status.governance.clone(),
            reason: GovernanceGuardReason::MissingPrivacyCommitments,
        }
    }

    fn dataspace_authority_conflict(lane: LaneId, status: Option<&LaneManifestStatus>) -> Self {
        Self {
            lane,
            alias: status.map_or_else(
                || format!("lane-{}", lane.as_u32()),
                |status| status.alias.clone(),
            ),
            governance: status.and_then(|status| status.governance.clone()),
            reason: GovernanceGuardReason::DataspaceAuthorityConflict,
        }
    }
}
/// Reasons surfaced when a lane is gated by governance/manifest checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceGuardReason {
    /// Lane is absent from the registry's exact active-catalog binding.
    UnknownLane,
    /// Lane requires a manifest but none was found.
    MissingManifest,
    /// Lane advertises commitment-only storage but has no privacy commitments configured.
    MissingPrivacyCommitments,
    /// Roster-bearing manifests in one physical dataspace declare different authority.
    DataspaceAuthorityConflict,
}
/// Shared registry handle.
pub type LaneManifestRegistryHandle = Arc<LaneManifestRegistry>;
impl fmt::Display for GovernanceGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}
impl std::error::Error for GovernanceGuardError {}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_config::parameters::actual::{
        GovernanceCatalog, GovernanceModule as ConfigGovernanceModule, LaneRegistry,
    };
    use iroha_data_model::{
        account::AccountId,
        nexus::{
            LaneCatalog, LaneConfig, NativeLaneMerkleCommitmentV1, NativeLanePrivacyCommitmentV1,
            NativeLaneValidatorBindingV1,
        },
    };
    use iroha_model_base::name::Name;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use nonzero_ext::nonzero;
    use std::{path::PathBuf, str::FromStr};
    use tempfile::tempdir;
    fn account_id_literal(account: &AccountId) -> String {
        account.to_string()
    }
    fn authority_rules_for_test(
        validators: Vec<AccountId>,
        quorum: Option<u32>,
    ) -> GovernanceRules {
        let validator_bindings = validators
            .iter()
            .map(|validator| ManifestValidatorBinding {
                validator: validator.clone(),
                peer_id: PeerId::from(validator.expect_single_signatory().clone()),
                torii_url: None,
            })
            .collect();
        GovernanceRules {
            validators,
            validator_bindings,
            quorum,
            ..GovernanceRules::default()
        }
    }

    fn manifest_status_for_test(
        lane: LaneId,
        dataspace: DataSpaceId,
        rules: GovernanceRules,
    ) -> LaneManifestStatus {
        LaneManifestStatus {
            lane,
            alias: format!("lane-{}", lane.as_u32()),
            dataspace,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: None,
            manifest_path: Some(PathBuf::from("/tmp/lane.manifest.json")),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        }
    }
    fn digest_fixture_registry(
        path: &str,
        validator: AccountId,
        quorum: u32,
        allow_runtime_upgrade: bool,
    ) -> LaneManifestRegistry {
        let peer_id = PeerId::from(validator.expect_single_signatory().clone());
        let rules = GovernanceRules {
            version: 1,
            validators: vec![validator.clone()],
            validator_bindings: vec![ManifestValidatorBinding {
                validator,
                peer_id,
                torii_url: Some("https://validator.example.com:8080".to_owned()),
            }],
            quorum: Some(quorum),
            protected_namespaces: BTreeSet::new(),
            hooks: GovernanceHooks {
                runtime_upgrade: Some(RuntimeUpgradeHook {
                    allow: allow_runtime_upgrade,
                    require_metadata: false,
                    metadata_key: None,
                    allowed_ids: None,
                }),
            },
        };
        let status = LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "governed".to_owned(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_owned()),
            manifest_path: Some(PathBuf::from(path)),
            governance_rules: Some(rules),
            privacy_commitments: Vec::new(),
        };
        LaneManifestRegistry::from_statuses(BTreeMap::from([(LaneId::SINGLE, status)]))
    }
    #[test]
    fn consensus_policy_digest_ignores_path_but_binds_committee_and_hooks() {
        let baseline = digest_fixture_registry("/srv/a.manifest.json", ALICE_ID.clone(), 1, true);
        let relocated =
            digest_fixture_registry("/different/a.manifest.json", ALICE_ID.clone(), 1, true);
        assert_eq!(
            baseline.consensus_policy_digest(),
            relocated.consensus_policy_digest(),
            "filesystem relocation must not change manifest semantics"
        );
        let validator_drift =
            digest_fixture_registry("/srv/a.manifest.json", BOB_ID.clone(), 1, true);
        assert_ne!(
            baseline.consensus_policy_digest(),
            validator_drift.consensus_policy_digest()
        );
        let quorum_drift =
            digest_fixture_registry("/srv/a.manifest.json", ALICE_ID.clone(), 2, true);
        assert_ne!(
            baseline.consensus_policy_digest(),
            quorum_drift.consensus_policy_digest()
        );
        let hook_drift =
            digest_fixture_registry("/srv/a.manifest.json", ALICE_ID.clone(), 1, false);
        assert_ne!(
            baseline.consensus_policy_digest(),
            hook_drift.consensus_policy_digest()
        );
    }
    #[test]
    fn source_policy_digest_binds_only_active_manifest_sources() {
        let first_dir = tempdir().expect("first manifest directory");
        let second_dir = tempdir().expect("second manifest directory");
        let compact = r#"{"lane":"future","version":1}"#;
        let formatted = "{\n  \"version\": 1,\n  \"lane\": \"future\"\n}\n";
        fs::write(first_dir.path().join("future.manifest.json"), compact)
            .expect("write compact future manifest");
        fs::write(second_dir.path().join("future.manifest.json"), formatted)
            .expect("write relocated formatted future manifest");
        let registry_for = |catalog: &LaneCatalog, directory: &Path| {
            LaneManifestRegistry::from_config(
                catalog,
                &GovernanceCatalog::default(),
                &LaneRegistry {
                    manifest_directory: Some(directory.to_path_buf()),
                    ..LaneRegistry::default()
                },
            )
        };
        let baseline = registry_for(&LaneCatalog::default(), first_dir.path());
        let relocated = registry_for(&LaneCatalog::default(), second_dir.path());
        assert_eq!(
            baseline.consensus_policy_digest(),
            relocated.consensus_policy_digest(),
            "unknown future manifests must not enter the startup source set"
        );
        assert!(!baseline.has_manifest_source_alias("future"));
        let expanded = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "future".to_owned(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("expanded catalog");
        let expanded_compact = registry_for(&expanded, first_dir.path());
        let expanded_formatted = registry_for(&expanded, second_dir.path());
        assert_ne!(
            baseline.consensus_policy_digest(),
            expanded_compact.consensus_policy_digest(),
            "a manifest enters the digest only when its lane alias is active"
        );
        assert_eq!(
            expanded_compact.consensus_policy_digest(),
            expanded_formatted.consensus_policy_digest(),
            "path and JSON formatting changes must not partition active peers"
        );
    }
    #[test]
    fn bounded_regular_source_read_accepts_boundary_and_rejects_overflow() {
        let dir = tempdir().expect("manifest directory");
        let path = dir.path().join("source.json");
        fs::write(&path, b"12345678").expect("write boundary source");
        assert_eq!(
            LaneManifestRegistry::read_bounded_regular_file(&path, 8)
                .expect("boundary source is accepted"),
            b"12345678"
        );
        fs::write(&path, b"123456789").expect("write overflow source");
        let error = LaneManifestRegistry::read_bounded_regular_file(&path, 8)
            .expect_err("max plus one must reject before an unbounded read");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[cfg(unix)]
    #[test]
    fn bounded_regular_source_read_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().expect("manifest directory");
        let target = dir.path().join("target.json");
        let link = dir.path().join("link.json");
        fs::write(&target, b"{}").expect("write target");
        symlink(&target, &link).expect("create source symlink");
        let error = LaneManifestRegistry::read_bounded_regular_file(&link, 8)
            .expect_err("symlink source must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    #[test]
    fn manifest_json_preflight_enforces_string_rule_and_depth_boundaries() {
        let limits = ManifestJsonLimits {
            max_string_bytes: 3,
            max_strings: 2,
            max_total_string_bytes: 2,
            max_rule_units: 4,
            max_depth: 1,
        };
        let footprint = LaneManifestRegistry::preflight_manifest_json(br#"{"a":"b"}"#, limits)
            .expect("exact preflight boundary is accepted");
        assert_eq!(footprint.strings, 2);
        assert_eq!(footprint.string_bytes, 2);
        assert_eq!(footprint.rule_units, 4);
        assert!(
            LaneManifestRegistry::preflight_manifest_json(br#"{"long":0}"#, limits).is_err(),
            "one over the per-string bound must reject"
        );
        assert!(
            LaneManifestRegistry::preflight_manifest_json(br#"{"aa":"bb"}"#, limits).is_err(),
            "one over the cumulative string-byte bound must reject"
        );
        assert!(
            LaneManifestRegistry::preflight_manifest_json(b"[0,0,0]", limits).is_err(),
            "one over the structural rule bound must reject"
        );
        assert!(
            LaneManifestRegistry::preflight_manifest_json(b"[[]]", limits).is_err(),
            "one over the nesting bound must reject"
        );
    }
    #[test]
    fn manifest_shape_and_aggregate_budgets_reject_overflow() {
        let mut manifest = NativeLaneManifestV1 {
            validators: Some(vec![
                NativeLaneValidatorBindingV1::default();
                LANE_MANIFEST_MAX_VALIDATORS_V1 + 1
            ]),
            ..NativeLaneManifestV1::default()
        };
        assert!(LaneManifestRegistry::validate_manifest_source_bounds(&manifest).is_err());
        manifest.validators = Some(vec![
            NativeLaneValidatorBindingV1::default();
            LANE_MANIFEST_MAX_VALIDATORS_V1
        ]);
        assert!(LaneManifestRegistry::validate_manifest_source_bounds(&manifest).is_ok());
        manifest.lane = Some("x".repeat(MANIFEST_SOURCE_MAX_IDENTIFIER_BYTES_V1 + 1));
        assert!(LaneManifestRegistry::validate_manifest_source_bounds(&manifest).is_err());
        let overlay = GovernanceCatalogFile {
            modules: (0..=GOVERNANCE_OVERLAY_MAX_MODULES_V1)
                .map(|index| (format!("module-{index}"), GovernanceModuleFile::default()))
                .collect(),
            ..GovernanceCatalogFile::default()
        };
        assert!(LaneManifestRegistry::validate_governance_overlay_source_bounds(&overlay).is_err());
        let mut budget = ManifestSourceLoadBudget {
            bytes: MANIFEST_SOURCE_AGGREGATE_MAX_BYTES_V1,
            strings: MANIFEST_SOURCE_AGGREGATE_MAX_STRINGS_V1,
            string_bytes: MANIFEST_SOURCE_AGGREGATE_MAX_STRING_BYTES_V1,
            rule_units: MANIFEST_SOURCE_AGGREGATE_MAX_RULE_UNITS_V1,
        };
        budget.charge_bytes(0).expect("exact byte boundary");
        budget
            .charge_json(ManifestJsonFootprint::default())
            .expect("exact JSON boundary");
        assert!(budget.charge_bytes(1).is_err());
        assert!(
            budget
                .charge_json(ManifestJsonFootprint {
                    strings: 1,
                    ..ManifestJsonFootprint::default()
                })
                .is_err()
        );
    }
    #[test]
    fn active_oversize_manifest_is_represented_as_invalid_without_full_read() {
        let dir = tempdir().expect("manifest directory");
        let path = dir.path().join("default.manifest.json");
        let file = fs::File::create(&path).expect("create sparse manifest");
        file.set_len(u64::try_from(LANE_MANIFEST_MAX_BYTES_V1 + 1).expect("bound fits u64"))
            .expect("extend sparse manifest");
        let registry = LaneManifestRegistry::from_config(
            &LaneCatalog::default(),
            &GovernanceCatalog::default(),
            &LaneRegistry {
                manifest_directory: Some(dir.path().to_path_buf()),
                ..LaneRegistry::default()
            },
        );
        assert!(registry.has_manifest_source_alias("default"));
        let source = registry
            .source_snapshot
            .as_ref()
            .expect("materialized snapshot")
            .manifests_by_alias
            .get("default")
            .expect("active source retained as invalid");
        assert!(
            source
                .parsed
                .as_ref()
                .expect_err("oversize source must be invalid")
                .contains("bounded")
        );
    }
    #[test]
    fn oversize_governance_overlay_is_represented_as_invalid_without_full_read() {
        let cache = tempdir().expect("manifest cache directory");
        let path = cache.path().join("governance_catalog.json");
        let file = fs::File::create(&path).expect("create sparse governance overlay");
        file.set_len(
            u64::try_from(GOVERNANCE_OVERLAY_MAX_BYTES_V1 + 1).expect("overlay bound fits u64"),
        )
        .expect("extend sparse governance overlay");
        let registry = LaneManifestRegistry::from_config(
            &LaneCatalog::default(),
            &GovernanceCatalog::default(),
            &LaneRegistry {
                cache_directory: Some(cache.path().to_path_buf()),
                ..LaneRegistry::default()
            },
        );
        let overlay = registry
            .source_snapshot
            .as_ref()
            .expect("materialized snapshot")
            .governance_overlay
            .as_ref()
            .expect("overlay retained as invalid");
        assert!(
            overlay
                .parsed
                .as_ref()
                .expect_err("oversize overlay must be invalid")
                .contains("bounded")
        );
    }
    #[test]
    fn unknown_sparse_manifest_does_not_enter_snapshot_or_digest() {
        let populated = tempdir().expect("populated manifest directory");
        let empty = tempdir().expect("empty manifest directory");
        let path = populated.path().join("future.manifest.json");
        let file = fs::File::create(&path).expect("create unknown sparse manifest");
        file.set_len(
            u64::try_from(LANE_MANIFEST_MAX_BYTES_V1 + 1).expect("manifest bound fits u64"),
        )
        .expect("extend unknown sparse manifest");
        let registry_for = |directory: &Path| {
            LaneManifestRegistry::from_config(
                &LaneCatalog::default(),
                &GovernanceCatalog::default(),
                &LaneRegistry {
                    manifest_directory: Some(directory.to_path_buf()),
                    ..LaneRegistry::default()
                },
            )
        };
        let skipped = registry_for(populated.path());
        let baseline = registry_for(empty.path());
        assert!(!skipped.has_manifest_source_alias("future"));
        assert_eq!(
            skipped.consensus_policy_digest(),
            baseline.consensus_policy_digest()
        );
    }
    #[test]
    fn frozen_source_rebind_ignores_post_load_file_drift_and_preserves_digest() {
        let dir = tempdir().expect("manifest directory");
        let path = dir.path().join("default.manifest.json");
        fs::write(&path, r#"{"lane":"default","version":1}"#).expect("write active manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(dir.path().to_path_buf()),
            ..LaneRegistry::default()
        };
        let lane_catalog = LaneCatalog::default();
        let governance = GovernanceCatalog::default();
        let baseline = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        let digest = baseline.consensus_policy_digest();
        fs::write(&path, b"{not-json").expect("drift manifest after startup");
        let rebound = baseline.rebind(&lane_catalog, &governance);
        assert_eq!(rebound.consensus_policy_digest(), digest);
        assert_eq!(
            rebound
                .lane_rules(LaneId::SINGLE)
                .expect("frozen active rules")
                .version,
            1
        );
        let freshly_loaded = LaneManifestRegistry::from_config(
            &lane_catalog,
            &GovernanceCatalog::default(),
            &registry_cfg,
        );
        assert_ne!(freshly_loaded.consensus_policy_digest(), digest);
        assert!(freshly_loaded.lane_rules(LaneId::SINGLE).is_none());
    }
    #[test]
    fn frozen_source_rebind_does_not_activate_unknown_future_manifest() {
        let dir = tempdir().expect("manifest directory");
        fs::write(
            dir.path().join("future.manifest.json"),
            r#"{"lane":"future","governance":"parliament","version":1}"#,
        )
        .expect("write future manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(dir.path().to_path_buf()),
            ..LaneRegistry::default()
        };
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_owned(), ConfigGovernanceModule::default());
        let baseline =
            LaneManifestRegistry::from_config(&LaneCatalog::default(), &governance, &registry_cfg);
        assert!(!baseline.has_manifest_source_alias("future"));
        let expanded = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "future".to_owned(),
                    governance: Some("parliament".to_owned()),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("expanded catalog");
        let rebound = baseline.rebind(&expanded, &governance);
        assert_eq!(
            rebound
                .ensure_lane_ready(LaneId::new(1))
                .expect_err("unknown future source must not be retained")
                .reason(),
            GovernanceGuardReason::MissingManifest
        );
        let explicitly_reloaded =
            LaneManifestRegistry::from_config(&expanded, &governance, &registry_cfg);
        assert!(
            explicitly_reloaded
                .ensure_lane_ready(LaneId::new(1))
                .is_ok()
        );
    }
    #[test]
    fn governed_or_private_lanes_without_frozen_semantics_fail_closed() {
        let baseline = LaneManifestRegistry::from_config(
            &LaneCatalog::default(),
            &GovernanceCatalog::default(),
            &LaneRegistry::default(),
        );
        let governed = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "unprovisioned".to_owned(),
                    governance: Some("parliament".to_owned()),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("governed catalog");
        let governed_registry = baseline.rebind(&governed, &GovernanceCatalog::default());
        assert_eq!(
            governed_registry
                .validate_active_coverage()
                .expect_err("unprovisioned governance must fail")
                .reason(),
            GovernanceGuardReason::MissingManifest
        );
        let private = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "private-unprovisioned".to_owned(),
                    storage: LaneStorageProfile::CommitmentOnly,
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("private catalog");
        let private_registry = baseline.rebind(&private, &GovernanceCatalog::default());
        assert_eq!(
            private_registry
                .ensure_lane_ready(LaneId::new(1))
                .expect_err("private lane without commitments must fail")
                .reason(),
            GovernanceGuardReason::MissingPrivacyCommitments
        );
        assert_eq!(
            private_registry
                .ensure_lane_ready(LaneId::new(99))
                .expect_err("unknown lane must fail")
                .reason(),
            GovernanceGuardReason::UnknownLane
        );
    }
    #[test]
    fn builder_allows_runtime_sources_but_requires_parsed_rules() {
        let status = LaneManifestStatus::builder(
            LaneId::new(7),
            "lane".to_string(),
            DataSpaceId::new(11),
            LaneVisibility::Public,
            LaneStorageProfile::default(),
        )
        .governance_rules(GovernanceRules::default())
        .build_ready()
        .expect("a runtime manifest needs no filesystem path");
        assert!(status.manifest_path.is_none());
        assert!(status.rules().is_some());
        let err = LaneManifestStatus::builder(
            LaneId::new(7),
            "lane".to_string(),
            DataSpaceId::new(11),
            LaneVisibility::Public,
            LaneStorageProfile::default(),
        )
        .manifest_path(Some(PathBuf::from("lane.manifest.json")))
        .build_ready()
        .expect_err("missing governance rules should fail");
        assert_eq!(err, LaneManifestBuilderError::MissingGovernanceRules);
    }
    #[test]
    fn privacy_commitments_parse_from_manifest() {
        let manifest = NativeLaneManifestV1 {
            lane: Some("private".to_string()),
            governance: Some("council".to_string()),
            privacy_commitments: Some(vec![NativeLanePrivacyCommitmentV1 {
                id: Some(1),
                scheme: Some("merkle".to_string()),
                merkle: Some(NativeLaneMerkleCommitmentV1 {
                    root: Some(
                        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_string(),
                    ),
                    max_depth: Some(16),
                }),
            }]),
            ..NativeLaneManifestV1::default()
        };
        let parsed = LaneManifestRegistry::parse_privacy_commitments("private", &manifest)
            .expect("commitments parsed");
        assert_eq!(parsed.len(), 1);
    }
    #[test]
    fn privacy_commitments_reject_snark_scheme_without_real_verifier() {
        let manifest = NativeLaneManifestV1 {
            lane: Some("private".to_string()),
            governance: Some("council".to_string()),
            privacy_commitments: Some(vec![NativeLanePrivacyCommitmentV1 {
                id: Some(2),
                scheme: Some("snark".to_string()),
                merkle: None,
            }]),
            ..NativeLaneManifestV1::default()
        };
        let err = LaneManifestRegistry::parse_privacy_commitments("private", &manifest)
            .expect_err("hash-only SNARK commitments must not be admitted");
        assert!(
            err.contains("only `merkle` is accepted"),
            "unexpected rejection: {err}"
        );
    }
    #[test]
    fn privacy_commitment_json_rejects_removed_snark_fields() {
        let raw = r#"{
            "privacy_commitments": [{
                "id": 2,
                "scheme": "snark",
                "snark": {
                    "circuit_id": 5,
                    "verifying_key_digest": "00",
                    "statement_hash": "00",
                    "proof_hash": "00"
                }
            }]
        }"#;
        let err = json::from_json::<NativeLaneManifestV1>(raw)
            .expect_err("removed SNARK fields must be rejected");
        assert!(
            err.to_string().contains("snark"),
            "unexpected rejection: {err}"
        );
    }
    #[test]
    fn commitment_only_lane_without_commitments_is_rejected() {
        let mut statuses = BTreeMap::new();
        statuses.insert(
            LaneId::new(1),
            LaneManifestStatus {
                lane: LaneId::new(1),
                alias: "private".to_string(),
                dataspace: DataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Restricted,
                storage: LaneStorageProfile::CommitmentOnly,
                governance: Some("council".to_string()),
                manifest_path: Some(PathBuf::from("/tmp/private.manifest.json")),
                governance_rules: Some(GovernanceRules::default()),
                privacy_commitments: Vec::new(),
            },
        );
        let registry = LaneManifestRegistry::from_statuses(statuses);
        let err = registry
            .ensure_lane_ready(LaneId::new(1))
            .expect_err("lane should be gated");
        assert_eq!(
            err.reason(),
            GovernanceGuardReason::MissingPrivacyCommitments
        );
    }
    #[test]
    fn commitment_only_lane_with_commitments_is_allowed() {
        let mut statuses = BTreeMap::new();
        let commitment = LanePrivacyCommitment::merkle(
            LaneCommitmentId::new(1),
            MerkleCommitment::from_root_bytes([0xAA; 32], 12),
        );
        statuses.insert(
            LaneId::new(2),
            LaneManifestStatus {
                lane: LaneId::new(2),
                alias: "private".to_string(),
                dataspace: DataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Restricted,
                storage: LaneStorageProfile::CommitmentOnly,
                governance: Some("council".to_string()),
                manifest_path: Some(PathBuf::from("/tmp/private.manifest.json")),
                governance_rules: Some(GovernanceRules::default()),
                privacy_commitments: vec![commitment],
            },
        );
        let registry = LaneManifestRegistry::from_statuses(statuses);
        assert!(registry.ensure_lane_ready(LaneId::new(2)).is_ok());
    }
    #[test]
    fn builder_produces_ready_status() {
        let rules = GovernanceRules {
            version: 2,
            quorum: Some(3),
            ..GovernanceRules::default()
        };
        let expected_rules = rules.clone();
        let manifest_path = PathBuf::from("lane.manifest.json");
        let status = LaneManifestStatus::builder(
            LaneId::new(3),
            "lane".to_string(),
            DataSpaceId::new(5),
            LaneVisibility::Restricted,
            LaneStorageProfile::SplitReplica,
        )
        .governance(Some("council".to_string()))
        .manifest_path(Some(manifest_path.clone()))
        .governance_rules(rules)
        .build_ready()
        .expect("builder should construct ready status");
        assert_eq!(status.lane, LaneId::new(3));
        assert_eq!(status.alias, "lane");
        assert_eq!(status.dataspace, DataSpaceId::new(5));
        assert_eq!(status.visibility, LaneVisibility::Restricted);
        assert_eq!(status.storage, LaneStorageProfile::SplitReplica);
        assert_eq!(status.governance.as_deref(), Some("council"));
        assert_eq!(status.manifest_path, Some(manifest_path));
        assert_eq!(status.rules(), Some(&expected_rules));
    }
    #[test]
    fn registry_detects_missing_manifest() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "governance".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let registry_cfg = LaneRegistry::default();
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        let err = registry
            .ensure_lane_ready(LaneId::new(0))
            .expect_err("missing manifest should trigger governance guard");
        assert_eq!(err.alias, "governance");
        assert_eq!(registry.missing_entries().len(), 1);
    }
    #[test]
    fn registry_loads_present_manifest() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        fs::write(&path, r#"{"lane":"gov","governance":"parliament"}"#).expect("write manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(path.parent().unwrap().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        assert!(
            registry.ensure_lane_ready(LaneId::new(0)).is_ok(),
            "manifest should satisfy governance guard"
        );
        assert!(registry.missing_entries().is_empty());
        let status = registry.status(LaneId::new(0)).expect("lane status");
        let rules = status.rules().expect("governance rules parsed");
        assert_eq!(rules.version, 1);
        assert!(rules.validators.is_empty());
        assert!(rules.protected_namespaces.is_empty());
    }
    #[test]
    fn registry_rejects_duplicate_manifest_aliases_in_directory() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        fs::write(
            dir.path().join("gov.manifest.json"),
            r#"{"lane":"gov","governance":"parliament"}"#,
        )
        .expect("write manifest");
        fs::write(
            dir.path().join("gov.json"),
            r#"{"lane":"gov","governance":"parliament"}"#,
        )
        .expect("write duplicate manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(dir.path().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        let err = registry
            .ensure_lane_ready(LaneId::new(0))
            .expect_err("duplicate manifest aliases must keep the lane locked");
        assert_eq!(err.reason(), GovernanceGuardReason::MissingManifest);
        assert_eq!(registry.missing_entries().len(), 1);
        let status = registry.status(LaneId::new(0)).expect("lane status");
        assert!(status.manifest_path.is_none());
    }
    #[test]
    fn cache_manifest_overrides_primary_directory() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let primary_dir = tempdir().expect("primary manifest directory");
        let cache_dir = tempdir().expect("cache manifest directory");
        fs::write(
            primary_dir.path().join("gov.manifest.json"),
            r#"{"lane":"gov","governance":"parliament","protected_namespaces":["primary"]}"#,
        )
        .expect("write primary manifest");
        fs::write(
            cache_dir.path().join("gov.manifest.json"),
            r#"{"lane":"gov","governance":"parliament","protected_namespaces":["cached"]}"#,
        )
        .expect("write cache manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(primary_dir.path().to_path_buf()),
            cache_directory: Some(cache_dir.path().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        let status = registry.status(LaneId::new(0)).expect("lane status");
        let rules = status.rules().expect("rules present");
        let expected_ns = Name::from_str("cached").expect("valid namespace");
        assert!(
            rules.protected_namespaces.contains(&expected_ns),
            "cache manifest should override namespaces"
        );
        assert_eq!(rules.protected_namespaces.len(), 1);
    }
    #[test]
    fn governance_overlay_supplies_missing_module() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "council".to_string(),
                governance: Some("council".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let governance = GovernanceCatalog::default();
        let cache_dir = tempdir().expect("cache manifest directory");
        fs::write(
            cache_dir.path().join("council.manifest.json"),
            r#"{"lane":"council","governance":"council"}"#,
        )
        .expect("write cache manifest");
        fs::write(
            cache_dir.path().join("governance_catalog.json"),
            r#"{"default_module":"council","modules":{"council":{"module_type":"council_multisig","params":{"quorum":"2"}}}}"#,
        )
        .expect("write governance overlay");
        let registry_cfg = LaneRegistry {
            manifest_directory: None,
            cache_directory: Some(cache_dir.path().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        let status = registry.status(LaneId::new(0)).expect("lane status");
        assert!(
            status.rules().is_some(),
            "overlay should supply governance module so manifest loads"
        );
        assert!(
            status.manifest_path.is_some(),
            "manifest from cache directory should be registered"
        );
    }
    #[test]
    fn governance_overlay_rejects_unknown_structural_fields() {
        for (index, source) in [
            br#"{"default_module":"council","moduels":{}}"#.as_slice(),
            br#"{"modules":{"council":{"module_type":"council_multisig","parameterz":{}}}}"#
                .as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let mut budget = ManifestSourceLoadBudget::default();
            let result =
                LaneManifestRegistry::parse_bounded_governance_overlay_json(source, &mut budget);
            assert!(
                result.is_err(),
                "unknown governance-overlay field case {index} must fail closed"
            );
        }
    }
    #[test]
    fn manifest_rejects_invalid_validator() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone());
        fs::write(
            &path,
            format!(
                r#"{{"lane":"gov","governance":"parliament","validators":[{{"validator":"not_an_account","peer_id":"{alice_peer}"}}]}}"#
            ),
        )
        .expect("write manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(path.parent().unwrap().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        assert!(registry.ensure_lane_ready(LaneId::new(0)).is_err());
    }
    #[test]
    fn manifest_rejects_quorum_larger_than_validator_set() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        let alice = account_id_literal(&ALICE_ID);
        let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone());
        fs::write(
            &path,
            format!(
                r#"{{"lane":"gov","governance":"parliament","validators":[{{"validator":"{alice}","peer_id":"{alice_peer}"}}],"quorum":2}}"#
            ),
        )
        .expect("write manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(path.parent().unwrap().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        assert!(registry.ensure_lane_ready(LaneId::new(0)).is_err());
    }
    #[test]
    fn manifest_rejects_quorum_without_validators() {
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        fs::write(
            &path,
            r#"{"lane":"gov","governance":"parliament","quorum":1}"#,
        )
        .expect("write manifest");

        let error = LaneManifestRegistry::validate_manifest(
            &path,
            LaneId::new(0),
            "gov",
            Some("parliament"),
            &governance,
        )
        .expect_err("quorum without an explicit validator set must fail closed");
        assert!(
            error.contains("quorum requires an explicit validator set"),
            "unexpected quorum-only manifest error: {error}"
        );
    }
    #[test]
    fn manifest_rejects_unknown_structural_fields_and_hooks() {
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let alice = account_id_literal(&ALICE_ID);
        let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone());
        let cases = [
            r#"{"lane":"gov","governance":"parliament","validatorz":[]}"#.to_owned(),
            format!(
                r#"{{"lane":"gov","governance":"parliament","validators":[{{"validator":"{alice}","peer_id":"{alice_peer}","weight":1}}]}}"#
            ),
            r#"{"lane":"gov","governance":"parliament","hooks":{"runtime_upgrdae":{"allow":false}}}"#.to_owned(),
            r#"{"lane":"gov","governance":"parliament","hooks":{"runtime_upgrade":{"alow":false}}}"#.to_owned(),
        ];

        for (index, source) in cases.into_iter().enumerate() {
            let dir = tempdir().expect("tmp dir");
            let path = dir.path().join("gov.manifest.json");
            fs::write(&path, source).expect("write manifest");
            let result = LaneManifestRegistry::validate_manifest(
                &path,
                LaneId::new(0),
                "gov",
                Some("parliament"),
                &governance,
            );
            assert!(
                result.is_err(),
                "unknown-field case {index} must fail closed"
            );
        }
    }
    #[test]
    fn manifest_parses_validators_and_namespaces() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        let alice = account_id_literal(&ALICE_ID);
        let bob = account_id_literal(&BOB_ID);
        let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone());
        let bob_peer = PeerId::from(BOB_ID.expect_single_signatory().clone());
        fs::write(
            &path,
            format!(
                r#"{{
                "lane": "gov",
                "governance": "parliament",
                "validators": [
                    {{"validator":"  {alice}  ","peer_id":" {alice_peer} ","torii_url":" https://alice.example.com:19080 "}},
                    {{"validator":"{bob}","peer_id":"{bob_peer}"}}
                ],
                "quorum": 2,
                "protected_namespaces": [" treasury ", "compliance"],
                "hooks": {{
                    "runtime_upgrade": {{
                        "allow": true,
                        "require_metadata": true,
                        "metadata_key": "gov_upgrade_id",
                        "allowed_ids": [" upgrade-q1 "]
                    }}
                }}
            }}"#
            ),
        )
        .expect("write manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(path.parent().unwrap().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        assert!(registry.ensure_lane_ready(LaneId::new(0)).is_ok());
        let rules = registry
            .lane_rules(LaneId::new(0))
            .expect("governance rules present");
        assert_eq!(rules.validators.len(), 2);
        assert_eq!(rules.validator_bindings.len(), 2);
        assert_eq!(rules.quorum, Some(2));
        assert_eq!(rules.protected_namespaces.len(), 2);
        assert_eq!(rules.validator_bindings[0].validator, ALICE_ID.clone());
        assert_eq!(rules.validator_bindings[0].peer_id, alice_peer);
        assert_eq!(
            rules.validator_bindings[0].torii_url.as_deref(),
            Some("https://alice.example.com:19080")
        );
        assert_eq!(rules.validator_bindings[1].validator, BOB_ID.clone());
        assert_eq!(rules.validator_bindings[1].peer_id, bob_peer);
        assert!(rules.validator_bindings[1].torii_url.is_none());
        let runtime_hook = rules
            .hooks
            .runtime_upgrade
            .as_ref()
            .expect("runtime upgrade hook parsed");
        assert!(runtime_hook.allow);
        assert!(runtime_hook.require_metadata);
        assert_eq!(
            runtime_hook
                .metadata_key
                .as_ref()
                .expect("metadata key")
                .as_ref(),
            "gov_upgrade_id"
        );
        let allowed_ids = runtime_hook
            .allowed_ids
            .as_ref()
            .expect("allowed ids present");
        assert!(allowed_ids.contains("upgrade-q1"));
    }
    #[test]
    fn manifest_rejects_duplicate_protected_namespace() {
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        fs::write(
            &path,
            r#"{"lane":"gov","governance":"parliament","protected_namespaces":[" treasury ","treasury"]}"#,
        )
        .expect("write manifest");
        let err = LaneManifestRegistry::validate_manifest(
            &path,
            LaneId::new(0),
            "gov",
            Some("parliament"),
            &governance,
        )
        .expect_err("duplicate protected namespace should fail manifest validation");
        assert!(
            err.contains("duplicate protected namespace"),
            "expected duplicate namespace rejection, got {err}"
        );
    }
    #[test]
    fn manifest_rejects_duplicate_runtime_upgrade_allowed_id() {
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        fs::write(
            &path,
            r#"{"lane":"gov","governance":"parliament","hooks":{"runtime_upgrade":{"allowed_ids":["upgrade-q1"," upgrade-q1 "]}}}"#,
        )
        .expect("write manifest");
        let err = LaneManifestRegistry::validate_manifest(
            &path,
            LaneId::new(0),
            "gov",
            Some("parliament"),
            &governance,
        )
        .expect_err("duplicate runtime upgrade allowed id should fail manifest validation");
        assert!(
            err.contains("allowed_ids entries must not duplicate values"),
            "expected duplicate runtime upgrade id rejection, got {err}"
        );
    }
    #[test]
    fn manifests_allow_validator_reuse_across_lanes() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(2_u32),
            vec![
                LaneConfig {
                    id: LaneId::new(0),
                    alias: "core".to_string(),
                    governance: Some("parliament".to_string()),
                    ..LaneConfig::default()
                },
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "payments".to_string(),
                    governance: Some("parliament".to_string()),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let alice = account_id_literal(&ALICE_ID);
        let bob = account_id_literal(&BOB_ID);
        let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone());
        let bob_peer = PeerId::from(BOB_ID.expect_single_signatory().clone());
        let manifest_body = format!(
            r#"{{
            "lane": "%ALIAS%",
            "governance": "parliament",
            "validators": [
                {{"validator":"{alice}","peer_id":"{alice_peer}"}},
                {{"validator":"{bob}","peer_id":"{bob_peer}"}}
            ],
            "quorum": 2
        }}"#
        );
        for alias in ["core", "payments"] {
            let path = dir.path().join(format!("{alias}.manifest.json"));
            let body = manifest_body.replace("%ALIAS%", alias);
            fs::write(&path, body).expect("write manifest");
        }
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(dir.path().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        assert!(registry.ensure_lane_ready(LaneId::new(0)).is_ok());
        assert!(registry.ensure_lane_ready(LaneId::new(1)).is_ok());
        assert!(
            registry.validate_active_coverage().is_ok(),
            "matching validator pools may be reused across lanes in one dataspace"
        );
        let core_validators = registry
            .lane_validators(LaneId::new(0))
            .expect("core validators parsed");
        let payments_validators = registry
            .lane_validators(LaneId::new(1))
            .expect("payments validators parsed");
        assert_eq!(core_validators.len(), 2);
        assert_eq!(payments_validators.len(), 2);
        assert_eq!(core_validators, payments_validators);
        assert_eq!(
            registry
                .lane_validator_bindings(LaneId::new(0))
                .expect("core validator bindings parsed")
                .len(),
            2
        );
        assert_eq!(
            registry
                .lane_validator_bindings(LaneId::new(1))
                .expect("payments validator bindings parsed")
                .len(),
            2
        );
        assert_eq!(registry.lane_quorum(LaneId::new(0)), Some(2));
        assert_eq!(registry.lane_quorum(LaneId::new(1)), Some(2));
    }
    #[test]
    fn dataspace_authority_projection_ignores_policy_only_target_manifest() {
        let source_lane = LaneId::new(0);
        let target_lane = LaneId::new(1);
        let dataspace = DataSpaceId::UNIVERSAL;
        let source_rules = authority_rules_for_test(vec![ALICE_ID.clone()], Some(1));
        let registry = LaneManifestRegistry::from_statuses(BTreeMap::from([
            (
                source_lane,
                manifest_status_for_test(source_lane, dataspace, source_rules),
            ),
            (
                target_lane,
                manifest_status_for_test(target_lane, dataspace, GovernanceRules::default()),
            ),
        ]));

        let projected = registry
            .dataspace_authority_rules(target_lane, dataspace)
            .expect("policy-only target must not conflict")
            .expect("source roster must project across its dataspace");
        assert_eq!(projected.validators, vec![ALICE_ID.clone()]);
        assert!(registry.validate_active_coverage().is_ok());
    }

    #[test]
    fn same_dataspace_manifest_pool_consistency_is_order_insensitive() {
        let lane_a = LaneId::new(0);
        let lane_b = LaneId::new(1);
        let dataspace = DataSpaceId::UNIVERSAL;
        let rules_a = authority_rules_for_test(vec![ALICE_ID.clone(), BOB_ID.clone()], Some(2));
        let mut rules_b = authority_rules_for_test(vec![BOB_ID.clone(), ALICE_ID.clone()], Some(2));
        rules_b.validator_bindings.reverse();
        for binding in &mut rules_b.validator_bindings {
            binding.torii_url = Some("https://alternate-route.example".to_owned());
        }
        let registry = LaneManifestRegistry::from_statuses(BTreeMap::from([
            (lane_a, manifest_status_for_test(lane_a, dataspace, rules_a)),
            (lane_b, manifest_status_for_test(lane_b, dataspace, rules_b)),
        ]));

        // This compares the owning dataspace's manifest pool. Autoscale's
        // immutable sampled committee remains a separate State-level concern.
        assert!(registry.validate_active_coverage().is_ok());
        assert!(
            registry
                .dataspace_authority_rules(lane_b, dataspace)
                .expect("equivalent pools must resolve")
                .is_some()
        );
    }

    #[test]
    fn conflicting_same_dataspace_manifest_pools_fail_closed() {
        let lane_a = LaneId::new(0);
        let lane_b = LaneId::new(1);
        let dataspace = DataSpaceId::UNIVERSAL;
        let registry = LaneManifestRegistry::from_statuses(BTreeMap::from([
            (
                lane_a,
                manifest_status_for_test(
                    lane_a,
                    dataspace,
                    authority_rules_for_test(vec![ALICE_ID.clone()], Some(1)),
                ),
            ),
            (
                lane_b,
                manifest_status_for_test(
                    lane_b,
                    dataspace,
                    authority_rules_for_test(vec![BOB_ID.clone()], Some(1)),
                ),
            ),
        ]));

        let err = registry
            .validate_active_coverage()
            .expect_err("one dataspace cannot advertise conflicting validator pools");
        assert_eq!(
            err.reason(),
            GovernanceGuardReason::DataspaceAuthorityConflict
        );
        assert!(
            registry
                .dataspace_authority_rules(lane_a, dataspace)
                .is_err(),
            "direct runtime lookup must fail closed even if validation was bypassed"
        );
    }

    #[test]
    fn catalog_aware_coverage_separates_static_and_autoscale_authority() {
        let static_lane_a = LaneId::new(0);
        let static_lane_b = LaneId::new(1);
        let autoscale_lane = LaneId::new(2);
        let dataspace = DataSpaceId::UNIVERSAL;
        let mut autoscale_config = LaneConfig {
            id: autoscale_lane,
            alias: "elastic-2".to_owned(),
            dataspace_id: dataspace,
            ..LaneConfig::default()
        };
        autoscale_config
            .metadata
            .insert(AUTOSCALE_META_MANAGED.to_owned(), "true".to_owned());
        autoscale_config
            .metadata
            .insert(AUTOSCALE_META_CREATED_HEIGHT.to_owned(), "1".to_owned());
        let catalog = LaneCatalog::new(
            nonzero!(3_u32),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: static_lane_b,
                    alias: "static-1".to_owned(),
                    dataspace_id: dataspace,
                    ..LaneConfig::default()
                },
                autoscale_config,
            ],
        )
        .expect("mixed static and autoscale catalog");

        let compatible_static_registry = LaneManifestRegistry::from_statuses(BTreeMap::from([
            (
                static_lane_a,
                manifest_status_for_test(
                    static_lane_a,
                    dataspace,
                    authority_rules_for_test(vec![ALICE_ID.clone()], Some(1)),
                ),
            ),
            (
                static_lane_b,
                manifest_status_for_test(
                    static_lane_b,
                    dataspace,
                    authority_rules_for_test(vec![ALICE_ID.clone()], Some(1)),
                ),
            ),
            (
                autoscale_lane,
                manifest_status_for_test(
                    autoscale_lane,
                    dataspace,
                    authority_rules_for_test(vec![BOB_ID.clone()], Some(1)),
                ),
            ),
        ]));
        assert!(
            compatible_static_registry
                .validate_active_coverage()
                .is_err(),
            "catalog-free validation remains conservative across the whole dataspace"
        );
        assert!(
            compatible_static_registry
                .validate_active_coverage_for_catalog(&catalog)
                .is_ok(),
            "an autoscale lane's exact authority must not conflict with static authority"
        );

        let conflicting_static_registry = LaneManifestRegistry::from_statuses(BTreeMap::from([
            (
                static_lane_a,
                manifest_status_for_test(
                    static_lane_a,
                    dataspace,
                    authority_rules_for_test(vec![ALICE_ID.clone()], Some(1)),
                ),
            ),
            (
                static_lane_b,
                manifest_status_for_test(
                    static_lane_b,
                    dataspace,
                    authority_rules_for_test(vec![BOB_ID.clone()], Some(1)),
                ),
            ),
            (
                autoscale_lane,
                manifest_status_for_test(
                    autoscale_lane,
                    dataspace,
                    authority_rules_for_test(vec![BOB_ID.clone()], Some(1)),
                ),
            ),
        ]));
        let err = conflicting_static_registry
            .validate_active_coverage_for_catalog(&catalog)
            .expect_err("static lanes in one dataspace must still share authority");
        assert_eq!(
            err.reason(),
            GovernanceGuardReason::DataspaceAuthorityConflict
        );
    }

    #[test]
    fn manifest_rejects_invalid_validator_torii_url() {
        LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        let alice = account_id_literal(&ALICE_ID);
        let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone());
        for rejected in [
            "not-a-url-REJECTED_INPUT_MARKER",
            "https://operator:REJECTED_INPUT_MARKER@validator.example",
            "https://validator.example?access_token=REJECTED_INPUT_MARKER",
            "https://validator.example#REJECTED_INPUT_MARKER",
        ] {
            fs::write(
                &path,
                format!(
                    r#"{{"lane":"gov","governance":"parliament","validators":[{{"validator":"{alice}","peer_id":"{alice_peer}","torii_url":"{rejected}"}}],"quorum":1}}"#
                ),
            )
            .expect("write synthetic rejected manifest");
            let err = LaneManifestRegistry::validate_manifest(
                &path,
                LaneId::new(0),
                "gov",
                Some("parliament"),
                &governance,
            )
            .expect_err("invalid torii_url should fail manifest validation");
            assert!(err.contains("torii_url"));
            assert!(!err.contains("REJECTED_INPUT_MARKER"));
            assert!(!err.contains(rejected));
        }
    }
    #[test]
    fn manifest_rejects_legacy_string_validator_entries() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        let alice = account_id_literal(&ALICE_ID);
        fs::write(
            &path,
            format!(r#"{{"lane":"gov","governance":"parliament","validators":["{alice}"]}}"#),
        )
        .expect("write manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(path.parent().unwrap().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        assert!(registry.ensure_lane_ready(LaneId::new(0)).is_err());
    }
    #[test]
    fn manifest_rejects_duplicate_validator_binding() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        let alice = account_id_literal(&ALICE_ID);
        let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone());
        let bob_peer = PeerId::from(BOB_ID.expect_single_signatory().clone());
        fs::write(
            &path,
            format!(
                r#"{{"lane":"gov","governance":"parliament","validators":[{{"validator":"{alice}","peer_id":"{alice_peer}"}},{{"validator":"{alice}","peer_id":"{bob_peer}"}}]}}"#
            ),
        )
        .expect("write manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(path.parent().unwrap().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        assert!(registry.ensure_lane_ready(LaneId::new(0)).is_err());
    }
    #[test]
    fn manifest_rejects_duplicate_peer_binding() {
        let lane_catalog = LaneCatalog::new(
            nonzero!(1_u32),
            vec![LaneConfig {
                id: LaneId::new(0),
                alias: "gov".to_string(),
                governance: Some("parliament".to_string()),
                ..LaneConfig::default()
            }],
        )
        .expect("valid catalog");
        let mut governance = GovernanceCatalog::default();
        governance
            .modules
            .insert("parliament".to_string(), ConfigGovernanceModule::default());
        let dir = tempdir().expect("tmp dir");
        let path = dir.path().join("gov.manifest.json");
        let alice = account_id_literal(&ALICE_ID);
        let bob = account_id_literal(&BOB_ID);
        let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone());
        fs::write(
            &path,
            format!(
                r#"{{"lane":"gov","governance":"parliament","validators":[{{"validator":"{alice}","peer_id":"{alice_peer}"}},{{"validator":"{bob}","peer_id":"{alice_peer}"}}]}}"#
            ),
        )
        .expect("write manifest");
        let registry_cfg = LaneRegistry {
            manifest_directory: Some(path.parent().unwrap().to_path_buf()),
            ..LaneRegistry::default()
        };
        let registry = LaneManifestRegistry::from_config(&lane_catalog, &governance, &registry_cfg);
        assert!(registry.ensure_lane_ready(LaneId::new(0)).is_err());
    }
}
