//! Compiled network profiles.
//!
//! A profile is a named, versioned bundle compiled into the binary from
//! `crates/iroha_config/profiles/<id>.toml`. It has four parts:
//!
//! - `[static]`: consensus-bound node configuration that does not depend on the roster size;
//! - `[derive]`: inputs to [`Profile::derive`], which computes the roster-dependent queue,
//!   byte and connection geometry, the `NPoS` `max_validators`, and the lane quorums;
//! - `[policy]` and `[host]`: deployment policy that is not consensus-bound;
//! - `[role.*]`: overlays for the `validator`, `lane_validator` and `observer` roles.
//!
//! `[genesis_recipe]` carries the genesis inputs a profile fixes. Together with `[static]` and
//! `derive(n)` it forms [`Profile::consensus_digest`]; `[policy]`, `[host]` and the role
//! overlays form [`Profile::policy_digest`]. Both hash canonical Norito encodings, never TOML
//! text.
//!
//! Node files that select a profile are loaded by [`crate::node_config`], which layers the
//! sources as defaults, `static`, `derive(n)`, `policy`, role overlay, node file, and admits
//! only [`PROFILE_NODE_KEYS`] (plus the profile's `node_tunable` keys) in the node file.

use iroha_config_base::{ReadConfig, read::ConfigReader, toml::TomlSource};
use iroha_crypto::Hash;
use iroha_data_model::block::consensus::ConsensusMode;
use norito::codec::{Decode, Encode};
use std::{collections::BTreeMap, fmt, path::PathBuf, str::FromStr, time::Duration};
use thiserror::Error;

pub mod canonical;

pub use canonical::{
    CanonicalEntryV1, CanonicalLeafV1, CanonicalPathSegmentV1, CanonicalTableV1,
    CanonicalValueError,
};

const SORA_NEXUS_V1: &str = include_str!("../profiles/sora-nexus-v1.toml");
const SORA_NEXUS_V1_QUAL: &str = include_str!("../profiles/sora-nexus-v1-qual.toml");
const IROHA_DEV_V1: &str = include_str!("../profiles/iroha-dev-v1.toml");

const CONSENSUS_DIGEST_DOMAIN: &[u8] = b"iroha:config:profile:consensus-digest:v1\0";
const POLICY_DIGEST_DOMAIN: &[u8] = b"iroha:config:profile:policy-digest:v1\0";

/// Derivation domain of a profile's keyless protocol custody account.
///
/// One account per base profile holds the gas technical account, the fee sink, the sponsor-vault
/// custody, the stake escrow and the slash sink, as Kagami's per-genesis gas-custody account did.
/// It is `derive_non_signing_ed25519_public_key(PROTOCOL_CUSTODY_ACCOUNT_DOMAIN, &[profile id])`,
/// so no signing key exists for it; the profile's `[static]` literals must equal
/// [`protocol_custody_account`].
pub const PROTOCOL_CUSTODY_ACCOUNT_DOMAIN: &[u8] = b"iroha:config:profile:protocol-custody:v1";

/// The keyless protocol custody account of a base profile (see
/// [`PROTOCOL_CUSTODY_ACCOUNT_DOMAIN`]). Profiles that extend a base use the base's account.
#[must_use]
pub fn protocol_custody_account(base: ProfileId) -> iroha_data_model::account::AccountId {
    iroha_data_model::account::AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
        PROTOCOL_CUSTODY_ACCOUNT_DOMAIN,
        &[base.as_str().as_bytes()],
    ))
}

/// Derivation domain of a profile's keyless role accounts ([`KeylessRole`]).
///
/// Each role account is `derive_non_signing_ed25519_public_key(KEYLESS_ROLE_ACCOUNT_DOMAIN,
/// &[profile id, role configuration key])`, so no signing key exists for it and every role has
/// its own account. The profile's literals must equal [`keyless_role_account`].
pub const KEYLESS_ROLE_ACCOUNT_DOMAIN: &[u8] = b"iroha:config:profile:keyless-role:v1";

/// An account role a profile fixes to a keyless account instead of a signing key.
///
/// The code defaults of these roles belong to the published sample key (`iroha_test_samples`
/// ALICE), so a public profile must never use them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeylessRole {
    /// `gov.citizenship_escrow_account`.
    CitizenshipEscrow,
    /// `gov.bond_escrow_account`.
    BondEscrow,
    /// `gov.slash_receiver_account`.
    SlashReceiver,
    /// `gov.viral_incentive_pool_account`.
    ViralIncentivePool,
    /// `gov.viral_escrow_account`.
    ViralEscrow,
    /// `gov.sorafs_pin_fee_treasury_account`.
    SorafsPinFeeTreasury,
    /// `network.soranet_vpn.operator_account_id` (deployment policy, not consensus-bound).
    SoranetVpnOperator,
}

impl KeylessRole {
    /// Every keyless role, in a stable order.
    pub const ALL: [Self; 7] = [
        Self::CitizenshipEscrow,
        Self::BondEscrow,
        Self::SlashReceiver,
        Self::ViralIncentivePool,
        Self::ViralEscrow,
        Self::SorafsPinFeeTreasury,
        Self::SoranetVpnOperator,
    ];

    /// Dotted configuration key the profile sets to this role's account.
    #[must_use]
    pub const fn config_key(self) -> &'static str {
        match self {
            Self::CitizenshipEscrow => "gov.citizenship_escrow_account",
            Self::BondEscrow => "gov.bond_escrow_account",
            Self::SlashReceiver => "gov.slash_receiver_account",
            Self::ViralIncentivePool => "gov.viral_incentive_pool_account",
            Self::ViralEscrow => "gov.viral_escrow_account",
            Self::SorafsPinFeeTreasury => "gov.sorafs_pin_fee_treasury_account",
            Self::SoranetVpnOperator => "network.soranet_vpn.operator_account_id",
        }
    }

    /// Whether the key belongs to the consensus-bound `[static]` part (otherwise `[policy]`).
    #[must_use]
    pub const fn is_static(self) -> bool {
        !matches!(self, Self::SoranetVpnOperator)
    }
}

/// The keyless account of `role` in a base profile (see [`KEYLESS_ROLE_ACCOUNT_DOMAIN`]).
/// Profiles that extend a base use the base's accounts.
#[must_use]
pub fn keyless_role_account(
    base: ProfileId,
    role: KeylessRole,
) -> iroha_data_model::account::AccountId {
    iroha_data_model::account::AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
        KEYLESS_ROLE_ACCOUNT_DOMAIN,
        &[base.as_str().as_bytes(), role.config_key().as_bytes()],
    ))
}

/// Per-node keys a profile node file may set, as dotted paths. An entry also admits every key
/// below it. The profile's `node_tunable` keys are admitted in addition.
pub const PROFILE_NODE_KEYS: &[&str] = &[
    "chain",
    "data_dir",
    "public_key",
    "trusted_peers",
    "trusted_peers_pop",
    "network.address",
    "network.public_address",
    "torii.address",
    "torii.transport.trusted_proxy_cidrs",
    "torii.operator_signatures.allowed_public_keys",
    "torii.account_onboarding.authority",
    "torii.account_onboarding.credentials",
    "torii.faucet.authority",
    "genesis",
    "soracloud_runtime.submission.signer",
    "soracloud_runtime.inrou.enabled",
    "soracloud_runtime.inrou.portable_vm_uid",
    "soracloud_runtime.inrou.portable_vm_gid",
    "soracloud_runtime.inrou.trusted_guest_manifest_digest_hex",
    "soracloud_runtime.inrou.trusted_guest_content_cid",
    "lifecycle.exit_on_stdin_close",
];

/// A compiled network profile identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileId {
    /// The public Taira shape.
    SoraNexusV1,
    /// `sora-nexus-v1` with qualification cadence, epoch length, snapshot interval and a
    /// 512 MiB storage budget.
    SoraNexusV1Qual,
    /// Developer defaults.
    IrohaDevV1,
}

impl ProfileId {
    /// Every compiled profile.
    pub const ALL: [Self; 3] = [Self::SoraNexusV1, Self::SoraNexusV1Qual, Self::IrohaDevV1];

    /// Canonical profile name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoraNexusV1 => "sora-nexus-v1",
            Self::SoraNexusV1Qual => "sora-nexus-v1-qual",
            Self::IrohaDevV1 => "iroha-dev-v1",
        }
    }

    const fn source(self) -> &'static str {
        match self {
            Self::SoraNexusV1 => SORA_NEXUS_V1,
            Self::SoraNexusV1Qual => SORA_NEXUS_V1_QUAL,
            Self::IrohaDevV1 => IROHA_DEV_V1,
        }
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProfileId {
    type Err = ProfileError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|id| id.as_str() == text)
            .ok_or_else(|| ProfileError::UnknownProfile(text.to_owned()))
    }
}

/// Role overlay selected by a node file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileRole {
    /// Member of the global roster.
    Validator,
    /// Owner-committee node: a global observer that signs its own lane.
    LaneValidator,
    /// Syncing, non-voting node.
    Observer,
}

impl ProfileRole {
    /// Every role overlay.
    pub const ALL: [Self; 3] = [Self::Validator, Self::LaneValidator, Self::Observer];

    /// Canonical overlay name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::LaneValidator => "lane_validator",
            Self::Observer => "observer",
        }
    }
}

impl fmt::Display for ProfileRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProfileRole {
    type Err = ProfileError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == text)
            .ok_or_else(|| ProfileError::UnknownRole(text.to_owned()))
    }
}

/// A profile that cannot be loaded, derived or digested.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileError {
    /// No compiled profile has this name.
    #[error("`{0}` is not a compiled profile (sora-nexus-v1 | sora-nexus-v1-qual | iroha-dev-v1)")]
    UnknownProfile(String),
    /// No role overlay has this name.
    #[error("`{0}` is not a role overlay (validator | lane_validator | observer)")]
    UnknownRole(String),
    /// The compiled profile text is malformed.
    #[error("profile `{profile}` is malformed: {message}")]
    Malformed {
        /// Profile being loaded.
        profile: ProfileId,
        /// What is wrong.
        message: String,
    },
    /// A consensus-bound key is also set by a mutable layer or admitted in node files.
    #[error("profile `{profile}`: consensus-bound key `{key}` is also set by `{layer}`")]
    StaticOverride {
        /// Profile being loaded.
        profile: ProfileId,
        /// Consensus-bound key.
        key: String,
        /// Layer that would override it.
        layer: String,
    },
    /// The roster cannot be admitted.
    #[error("profile `{profile}` cannot derive a roster of {validators}: {reason}")]
    Geometry {
        /// Profile being derived.
        profile: ProfileId,
        /// Requested roster.
        validators: usize,
        /// Why the roster is not admissible.
        reason: &'static str,
    },
    /// A value has no canonical form.
    #[error("profile `{profile}`: {source}")]
    Canonical {
        /// Profile being digested.
        profile: ProfileId,
        /// Canonicalization failure.
        source: CanonicalValueError,
    },
    /// Canonical Norito encoding failed.
    #[error("profile `{profile}` digest input cannot be encoded: {message}")]
    Codec {
        /// Profile being digested.
        profile: ProfileId,
        /// Codec diagnostic.
        message: String,
    },
}

/// Genesis inputs a profile fixes. Part of the consensus digest.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_config::profile::GenesisRecipeV1")]
pub struct GenesisRecipeV1 {
    /// `"npos"` or `"permissioned"`.
    pub consensus_mode: String,
    /// Signed block cadence.
    pub block_cadence_ms: u64,
    /// `NPoS` epoch length.
    pub epoch_length_blocks: u64,
    /// Signed per-block transaction ceiling.
    pub block_max_transactions: u64,
    /// Signed IVM gas budget per block.
    pub ivm_gas_limit_per_block: u64,
    /// `NPoS` minimum self bond.
    pub npos_min_self_bond: u64,
}

impl GenesisRecipeV1 {
    /// Consensus mode selected by genesis.
    ///
    /// # Panics
    ///
    /// Never for a loaded profile: the mode is validated when the profile is compiled.
    #[must_use]
    pub fn consensus_mode(&self) -> ConsensusMode {
        parse_consensus_mode(&self.consensus_mode).expect("validated when the profile loads")
    }

    /// Signed block cadence.
    #[must_use]
    pub fn block_cadence(&self) -> Duration {
        Duration::from_millis(self.block_cadence_ms)
    }
}

fn parse_consensus_mode(text: &str) -> Option<ConsensusMode> {
    match text {
        "npos" => Some(ConsensusMode::Npos),
        "permissioned" => Some(ConsensusMode::Permissioned),
        _ => None,
    }
}

/// Inputs of [`Profile::derive`].
#[derive(Debug, Clone, PartialEq)]
pub struct DeriveInputs {
    /// Connections each validator admits for authenticated non-validator peers (arbitrary
    /// observers, first come).
    pub authenticated_non_validator_sources: u32,
    /// On-chain budget of external committee peers; `committee_sources = n + this`.
    pub max_external_committee_peers: u32,
    /// Dataspace catalog template; [`Profile::derive`] adds each entry's `fault_tolerance`.
    pub dataspace_catalog: Vec<toml::Table>,
}

/// Host deployment policy that is not node configuration. Part of the policy digest.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_config::profile::HostPolicyV1")]
pub struct HostPolicyV1 {
    /// systemd `MemoryMax=`.
    pub systemd_memory_max: String,
    /// systemd `CPUQuota=`.
    pub systemd_cpu_quota: String,
    /// Default remote P2P port.
    pub p2p_port: u16,
    /// Default remote Torii port.
    pub torii_port: u16,
}

/// Roster-dependent values computed by [`Profile::derive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_config::profile::DerivedGeometryV1")]
pub struct DerivedGeometryV1 {
    /// Roster size `n = 3f + 1`, also the signed `NPoS` `max_validators`.
    pub validators: u32,
    /// Tolerated faults `f`, used as every dataspace's `fault_tolerance`.
    pub fault_tolerance: u32,
    /// Commit quorum `2f + 1`.
    pub commit_quorum: u32,
    /// Committee peer budget `n + max_external_committee_peers`.
    pub committee_sources: u32,
    /// Connections reserved for authenticated non-validator peers.
    pub authenticated_non_validator_sources: u32,
    /// `network.max_total_connections`: every other validator, external committee peer and
    /// authenticated non-validator peer.
    pub max_total_connections: u64,
    /// Genesis `NPoS` `max_validators`.
    pub npos_max_validators: u32,
}

/// A 32-byte profile digest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_config::profile::ProfileDigest")]
pub struct ProfileDigest(pub [u8; 32]);

impl fmt::Display for ProfileDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// Canonical input of [`Profile::consensus_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_config::profile::ConsensusDigestInputV1")]
pub struct ConsensusDigestInputV1 {
    /// Profile name.
    pub profile: String,
    /// Profile version.
    pub version: u32,
    /// Chain discriminant the profile's account literals use.
    pub chain_discriminant: u16,
    /// `[static]`.
    pub static_config: CanonicalTableV1,
    /// Configuration fragment produced by `derive(n)`.
    pub derived_config: CanonicalTableV1,
    /// Geometry produced by `derive(n)`.
    pub geometry: DerivedGeometryV1,
    /// `[genesis_recipe]`.
    pub genesis_recipe: GenesisRecipeV1,
}

/// Canonical input of [`Profile::policy_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_config::profile::PolicyDigestInputV1")]
pub struct PolicyDigestInputV1 {
    /// Profile name.
    pub profile: String,
    /// Profile version.
    pub version: u32,
    /// Node-tunable keys.
    pub node_tunable: Vec<String>,
    /// `[policy]`.
    pub policy: CanonicalTableV1,
    /// `[host]`.
    pub host: HostPolicyV1,
    /// `[role.*]`, keyed by role name.
    pub roles: BTreeMap<String, CanonicalTableV1>,
}

/// A loaded compiled profile.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    id: ProfileId,
    version: u32,
    chain_discriminant: u16,
    node_tunable: Vec<String>,
    genesis_recipe: GenesisRecipeV1,
    static_config: toml::Table,
    derive: DeriveInputs,
    policy: toml::Table,
    host: HostPolicyV1,
    roles: BTreeMap<ProfileRole, toml::Table>,
}

#[derive(ReadConfig)]
struct ProfileFile {
    #[config(nested)]
    profile: ProfileHeader,
    #[config(nested)]
    genesis_recipe: GenesisRecipeFile,
    #[config(nested)]
    derive: DeriveFile,
    #[config(nested)]
    host: HostFile,
}

#[derive(ReadConfig)]
struct ProfileHeader {
    id: String,
    version: u32,
    chain_discriminant: u16,
    #[config(default)]
    node_tunable: Vec<String>,
}

#[derive(ReadConfig)]
struct GenesisRecipeFile {
    consensus_mode: String,
    block_cadence_ms: u64,
    epoch_length_blocks: u64,
    block_max_transactions: u64,
    ivm_gas_limit_per_block: u64,
    npos_min_self_bond: u64,
}

#[derive(ReadConfig)]
struct DeriveFile {
    authenticated_non_validator_sources: u32,
    max_external_committee_peers: u32,
}

#[derive(ReadConfig)]
struct HostFile {
    systemd_memory_max: String,
    systemd_cpu_quota: String,
    p2p_port: u16,
    torii_port: u16,
}

/// Node-configuration fragments of a profile file, removed before its typed sections are read.
struct OpaqueSections {
    static_config: toml::Table,
    policy: toml::Table,
    roles: BTreeMap<ProfileRole, toml::Table>,
    dataspace_catalog: Vec<toml::Table>,
}

impl OpaqueSections {
    fn take(id: ProfileId, table: &mut toml::Table) -> Result<Self, ProfileError> {
        let malformed = |message: String| ProfileError::Malformed {
            profile: id,
            message,
        };
        let take_table = |table: &mut toml::Table, key: &str| match table.remove(key) {
            Some(toml::Value::Table(section)) => Ok(section),
            Some(_) => Err(malformed(format!("`{key}` must be a table"))),
            None => Err(malformed(format!("missing `[{key}]`"))),
        };
        let static_config = take_table(table, "static")?;
        let policy = take_table(table, "policy")?;
        let mut role_tables = take_table(table, "role")?;
        let mut roles = BTreeMap::new();
        for role in ProfileRole::ALL {
            roles.insert(role, take_table(&mut role_tables, role.as_str())?);
        }
        if let Some(extra) = role_tables.keys().next() {
            return Err(malformed(format!("unknown role overlay `role.{extra}`")));
        }
        let dataspace_catalog = match table
            .get_mut("derive")
            .and_then(toml::Value::as_table_mut)
            .and_then(|derive| derive.remove("dataspace_catalog"))
        {
            None => Vec::new(),
            Some(toml::Value::Array(entries)) => entries
                .into_iter()
                .map(|entry| match entry {
                    toml::Value::Table(entry) => Ok(entry),
                    _ => Err(malformed(
                        "`derive.dataspace_catalog` entries must be tables".to_owned(),
                    )),
                })
                .collect::<Result<_, _>>()?,
            Some(_) => {
                return Err(malformed(
                    "`derive.dataspace_catalog` must be an array of tables".to_owned(),
                ));
            }
        };
        Ok(Self {
            static_config,
            policy,
            roles,
            dataspace_catalog,
        })
    }
}

impl Profile {
    /// Load one compiled profile, resolving its `extends` base.
    ///
    /// # Errors
    ///
    /// [`ProfileError`] when the compiled text is malformed or a consensus-bound key can be
    /// overridden by a mutable layer or a node file.
    pub fn compiled(id: ProfileId) -> Result<Self, ProfileError> {
        let malformed = |message: String| ProfileError::Malformed {
            profile: id,
            message,
        };
        let mut table = parse_profile_text(id)?;
        let base = table
            .get_mut("profile")
            .and_then(toml::Value::as_table_mut)
            .and_then(|header| header.remove("extends"));
        if let Some(base) = base {
            let base = base
                .as_str()
                .ok_or_else(|| malformed("`profile.extends` must be a profile name".to_owned()))?
                .parse::<ProfileId>()?;
            let mut base_table = parse_profile_text(base)?;
            if base_table
                .get("profile")
                .and_then(toml::Value::as_table)
                .is_some_and(|header| header.contains_key("extends"))
            {
                return Err(malformed(format!(
                    "base profile `{base}` must not extend another profile"
                )));
            }
            deep_merge(&mut base_table, table);
            table = base_table;
        }
        Self::from_table(id, table)
    }

    fn from_table(id: ProfileId, mut table: toml::Table) -> Result<Self, ProfileError> {
        let malformed = |message: String| ProfileError::Malformed {
            profile: id,
            message,
        };
        let OpaqueSections {
            static_config,
            policy,
            roles,
            dataspace_catalog,
        } = OpaqueSections::take(id, &mut table)?;
        let file = ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::new(
                PathBuf::from(format!("<profile {id}>")),
                table,
            ))
            .read_and_complete::<ProfileFile>()
            .map_err(|report| malformed(format!("{report:?}")))?;
        if file.profile.id != id.as_str() {
            return Err(malformed(format!(
                "`profile.id` is `{}`, expected `{id}`",
                file.profile.id
            )));
        }
        if parse_consensus_mode(&file.genesis_recipe.consensus_mode).is_none() {
            return Err(malformed(format!(
                "`genesis_recipe.consensus_mode` `{}` is not `npos` or `permissioned`",
                file.genesis_recipe.consensus_mode
            )));
        }
        let profile = Self {
            id,
            version: file.profile.version,
            chain_discriminant: file.profile.chain_discriminant,
            node_tunable: file.profile.node_tunable,
            genesis_recipe: GenesisRecipeV1 {
                consensus_mode: file.genesis_recipe.consensus_mode,
                block_cadence_ms: file.genesis_recipe.block_cadence_ms,
                epoch_length_blocks: file.genesis_recipe.epoch_length_blocks,
                block_max_transactions: file.genesis_recipe.block_max_transactions,
                ivm_gas_limit_per_block: file.genesis_recipe.ivm_gas_limit_per_block,
                npos_min_self_bond: file.genesis_recipe.npos_min_self_bond,
            },
            static_config,
            derive: DeriveInputs {
                authenticated_non_validator_sources: file
                    .derive
                    .authenticated_non_validator_sources,
                max_external_committee_peers: file.derive.max_external_committee_peers,
                dataspace_catalog,
            },
            policy,
            host: HostPolicyV1 {
                systemd_memory_max: file.host.systemd_memory_max,
                systemd_cpu_quota: file.host.systemd_cpu_quota,
                p2p_port: file.host.p2p_port,
                torii_port: file.host.torii_port,
            },
            roles,
        };
        profile.validate_layering()?;
        Ok(profile)
    }

    /// Consensus-bound keys (`[static]` and the `derive(n)` fragment) must not be reachable by
    /// the policy layer, a role overlay or a node file.
    fn validate_layering(&self) -> Result<(), ProfileError> {
        let mut consensus_keys = leaf_keys(&self.static_config);
        let derived_keys = leaf_keys(&self.derived_config_template());
        if let Some(key) = consensus_keys.iter().find(|key| {
            derived_keys
                .iter()
                .any(|derived| keys_overlap(key, derived))
        }) {
            return Err(ProfileError::StaticOverride {
                profile: self.id,
                key: key.clone(),
                layer: "derive(n)".to_owned(),
            });
        }
        consensus_keys.extend(derived_keys);
        consensus_keys.push("chain_discriminant".to_owned());
        let mut mutable_layers = vec![("policy".to_owned(), leaf_keys(&self.policy))];
        for (role, table) in &self.roles {
            mutable_layers.push((format!("role.{role}"), leaf_keys(table)));
        }
        for key in &consensus_keys {
            for (layer, keys) in &mutable_layers {
                if keys.iter().any(|other| keys_overlap(key, other)) {
                    return Err(ProfileError::StaticOverride {
                        profile: self.id,
                        key: key.clone(),
                        layer: layer.clone(),
                    });
                }
            }
            if self.admits_node_key(key) {
                return Err(ProfileError::StaticOverride {
                    profile: self.id,
                    key: key.clone(),
                    layer: "node file".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Profile identifier.
    #[must_use]
    pub fn id(&self) -> ProfileId {
        self.id
    }

    /// Profile version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Chain discriminant the profile's account literals are encoded for.
    #[must_use]
    pub fn chain_discriminant(&self) -> u16 {
        self.chain_discriminant
    }

    /// Keys a node file may tune in addition to [`PROFILE_NODE_KEYS`].
    #[must_use]
    pub fn node_tunable(&self) -> &[String] {
        &self.node_tunable
    }

    /// Genesis inputs.
    #[must_use]
    pub fn genesis_recipe(&self) -> &GenesisRecipeV1 {
        &self.genesis_recipe
    }

    /// Inputs of [`Self::derive`].
    #[cfg(test)]
    #[must_use]
    pub fn derive_inputs(&self) -> &DeriveInputs {
        &self.derive
    }

    /// Host deployment policy.
    #[must_use]
    pub fn host(&self) -> &HostPolicyV1 {
        &self.host
    }

    /// `[static]` node-configuration fragment.
    #[must_use]
    pub fn static_config(&self) -> &toml::Table {
        &self.static_config
    }

    /// `[policy]` node-configuration fragment.
    #[must_use]
    pub fn policy(&self) -> &toml::Table {
        &self.policy
    }

    /// One role overlay.
    #[must_use]
    pub fn role(&self, role: ProfileRole) -> &toml::Table {
        &self.roles[&role]
    }

    /// Whether a node file of this profile may set `key` (dotted).
    #[must_use]
    pub fn admits_node_key(&self, key: &str) -> bool {
        PROFILE_NODE_KEYS
            .iter()
            .copied()
            .chain(self.node_tunable.iter().map(String::as_str))
            .any(|allowed| key == allowed || is_below(key, allowed))
    }

    /// Admit a roster of `n` validators and compute its geometry.
    ///
    /// The roster must be an exact Sumeragi `3f + 1` committee. The geometry fixes `f`, the
    /// `2f + 1` commit quorum, the committee peer budget `n + max_external_committee_peers`,
    /// the genesis `NPoS` `max_validators = n`, and `network.max_total_connections`, which
    /// admits every other validator, every external committee peer and the authenticated
    /// non-validator allowance. Sumeragi takes no roster-dependent node configuration: its
    /// committee comes from signed genesis and committed state.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Geometry`] for a roster that is not `3f + 1` or whose derived sizes
    /// overflow the platform representation.
    pub fn derive(&self, validators: usize) -> Result<DerivedGeometryV1, ProfileError> {
        let reject = |reason| ProfileError::Geometry {
            profile: self.id,
            validators,
            reason,
        };
        if !iroha_data_model::block::consensus::is_valid_committee_size(validators) {
            return Err(reject(
                "the global committee must have exactly 3f + 1 validators with 1 <= f <= 10",
            ));
        }
        let overflow = || reject("the derived sizes overflow the platform representation");
        let authenticated = to_usize(self.derive.authenticated_non_validator_sources);
        let external = to_usize(self.derive.max_external_committee_peers);
        let committee_sources = validators.checked_add(external).ok_or_else(overflow)?;
        let max_total_connections = (validators - 1)
            .checked_add(external)
            .and_then(|peers| peers.checked_add(authenticated))
            .ok_or_else(overflow)?;
        let fault_tolerance = u32::try_from((validators - 1) / 3).map_err(|_| overflow())?;
        Ok(DerivedGeometryV1 {
            validators: u32::try_from(validators).map_err(|_| overflow())?,
            fault_tolerance,
            commit_quorum: 2 * fault_tolerance + 1,
            committee_sources: u32::try_from(committee_sources).map_err(|_| overflow())?,
            authenticated_non_validator_sources: self.derive.authenticated_non_validator_sources,
            max_total_connections: u64::try_from(max_total_connections).map_err(|_| overflow())?,
            npos_max_validators: u32::try_from(validators).map_err(|_| overflow())?,
        })
    }

    /// Node-configuration fragment produced by `derive(n)`.
    #[must_use]
    pub fn derived_config(&self, geometry: &DerivedGeometryV1) -> toml::Table {
        let integer = |value: u64| toml::Value::Integer(i64::try_from(value).unwrap_or(i64::MAX));
        let mut network = toml::Table::new();
        network.insert(
            "max_total_connections".into(),
            integer(geometry.max_total_connections),
        );
        let mut fragment = toml::Table::new();
        fragment.insert("network".into(), toml::Value::Table(network));
        if !self.derive.dataspace_catalog.is_empty() {
            let catalog = self
                .derive
                .dataspace_catalog
                .iter()
                .map(|entry| {
                    let mut entry = entry.clone();
                    entry.insert(
                        "fault_tolerance".into(),
                        integer(u64::from(geometry.fault_tolerance)),
                    );
                    toml::Value::Table(entry)
                })
                .collect();
            let mut nexus = toml::Table::new();
            nexus.insert("dataspace_catalog".into(), toml::Value::Array(catalog));
            fragment.insert("nexus".into(), toml::Value::Table(nexus));
        }
        fragment
    }

    /// Keys of the `derive(n)` fragment, independent of `n`.
    fn derived_config_template(&self) -> toml::Table {
        self.derived_config(&DerivedGeometryV1 {
            validators: 4,
            fault_tolerance: 1,
            commit_quorum: 3,
            committee_sources: 0,
            authenticated_non_validator_sources: 0,
            max_total_connections: 0,
            npos_max_validators: 4,
        })
    }

    /// `H(static ‖ derive(n) ‖ genesis recipe)` for a roster of `n` validators.
    ///
    /// # Errors
    ///
    /// Any error of [`Self::derive`], or a value without canonical form.
    pub fn consensus_digest(&self, validators: usize) -> Result<ProfileDigest, ProfileError> {
        let geometry = self.derive(validators)?;
        self.consensus_digest_for(&geometry)
    }

    /// Consensus digest for an already derived geometry.
    ///
    /// # Errors
    ///
    /// A value without canonical form, or a codec failure.
    pub fn consensus_digest_for(
        &self,
        geometry: &DerivedGeometryV1,
    ) -> Result<ProfileDigest, ProfileError> {
        let input = ConsensusDigestInputV1 {
            profile: self.id.as_str().to_owned(),
            version: self.version,
            chain_discriminant: self.chain_discriminant,
            static_config: self.canonical(&self.static_config)?,
            derived_config: self.canonical(&self.derived_config(geometry))?,
            geometry: *geometry,
            genesis_recipe: self.genesis_recipe.clone(),
        };
        self.digest(CONSENSUS_DIGEST_DOMAIN, &input)
    }

    /// `H(policy ‖ roles)`, including `[host]` and the node-tunable keys.
    ///
    /// # Errors
    ///
    /// A value without canonical form, or a codec failure.
    pub fn policy_digest(&self) -> Result<ProfileDigest, ProfileError> {
        let roles = self
            .roles
            .iter()
            .map(|(role, table)| Ok((role.as_str().to_owned(), self.canonical(table)?)))
            .collect::<Result<_, ProfileError>>()?;
        let input = PolicyDigestInputV1 {
            profile: self.id.as_str().to_owned(),
            version: self.version,
            node_tunable: self.node_tunable.clone(),
            policy: self.canonical(&self.policy)?,
            host: self.host.clone(),
            roles,
        };
        self.digest(POLICY_DIGEST_DOMAIN, &input)
    }

    fn canonical(&self, table: &toml::Table) -> Result<CanonicalTableV1, ProfileError> {
        CanonicalTableV1::from_table(table).map_err(|source| ProfileError::Canonical {
            profile: self.id,
            source,
        })
    }

    fn digest<T: norito::NoritoSerialize>(
        &self,
        domain: &[u8],
        input: &T,
    ) -> Result<ProfileDigest, ProfileError> {
        let encoded = norito::encode_canonical(input).map_err(|error| ProfileError::Codec {
            profile: self.id,
            message: error.to_string(),
        })?;
        Ok(ProfileDigest(
            Hash::new_from_chunks(&[domain, encoded.as_slice()]).into(),
        ))
    }

    /// Profile layers for one node, lowest precedence first: `static`, `derive(n)`, `policy`,
    /// and the role overlay. The static source also supplies the profile's account
    /// address discriminant, so node files never repeat network-owned identity.
    #[must_use]
    pub fn layers(&self, geometry: &DerivedGeometryV1, role: ProfileRole) -> Vec<TomlSource> {
        let source = |layer: String, table: toml::Table| {
            TomlSource::new(
                PathBuf::from(format!("<profile {}>/{layer}", self.id)),
                table,
            )
        };
        let mut static_config = self.static_config.clone();
        static_config.insert(
            "chain_discriminant".to_owned(),
            toml::Value::Integer(i64::from(self.chain_discriminant)),
        );
        vec![
            source("static".to_owned(), static_config),
            source(
                format!("derive({})", geometry.validators),
                self.derived_config(geometry),
            ),
            source("policy".to_owned(), self.policy.clone()),
            source(format!("role.{role}"), self.roles[&role].clone()),
        ]
    }
}

fn parse_profile_text(id: ProfileId) -> Result<toml::Table, ProfileError> {
    toml::from_str(id.source()).map_err(|error| ProfileError::Malformed {
        profile: id,
        message: error.to_string(),
    })
}

fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("u32 fits usize on supported targets")
}

/// Merge `overlay` into `base`: tables merge recursively, every other value replaces.
pub(crate) fn deep_merge(base: &mut toml::Table, overlay: toml::Table) {
    for (key, value) in overlay {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(base)), toml::Value::Table(overlay)) => {
                deep_merge(base, overlay);
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// Dotted keys of every non-table value; arrays are leaves.
pub(crate) fn leaf_keys(table: &toml::Table) -> Vec<String> {
    fn walk(table: &toml::Table, prefix: &str, keys: &mut Vec<String>) {
        for (key, value) in table {
            let path = canonical::join_path(prefix, key);
            match value {
                toml::Value::Table(table) => walk(table, &path, keys),
                _ => keys.push(path),
            }
        }
    }
    let mut keys = Vec::new();
    walk(table, "", &mut keys);
    keys
}

/// Whether `key` lies strictly below `ancestor`.
pub(crate) fn is_below(key: &str, ancestor: &str) -> bool {
    key.strip_prefix(ancestor)
        .is_some_and(|rest| rest.starts_with('.'))
}

fn keys_overlap(left: &str, right: &str) -> bool {
    left == right || is_below(left, right) || is_below(right, left)
}

#[cfg(test)]
mod tests;
