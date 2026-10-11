//! Canonical native localnet generation shared by desktop and CLI frontends.

mod custody;
pub mod service_authorities;
use crate::genesis::{
    ConsensusPolicy, generate_default,
    profile::{
        PUBLIC_NEXUS_CHAIN_ID, PUBLIC_TAIRA_CHAIN_ID, TAIRA_XOR_ASSET_DEFINITION_ID,
        known_chain_discriminant_for_chain_id, reject_retired_public_chain_id,
    },
    validate_consensus_mode,
};
use color_eyre::eyre::{Result, WrapErr as _, ensure, eyre};
use iroha_config::{
    base::toml::TomlSource,
    parameters::{actual, defaults::taira as taira_defaults},
};
use iroha_core::state::derive_committee_key_id;
use iroha_core_zk::confidential_v2;
use iroha_crypto::{ExposedPrivateKey, Hash, HashOf, KeyPair};
#[cfg(test)]
use iroha_data_model::isi::UnregisterBox;
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    alias_setup::{
        AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
        AliasDataSpaceIntentV1, AliasDomainIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1,
        AliasQuoteGuardV1, AliasSetupPlanRequestV1, ResolvedAccountAliasV1, ResolvedDataSpaceV1,
        ResolvedDomainV1,
    },
    asset::AssetDefinitionAlias,
    block::{
        BlockHeader,
        consensus::{
            MAX_VALIDATORS_PER_HEIGHT, SumeragiGenesisContextParameters, SumeragiRootScope,
            is_valid_committee_size,
        },
    },
    consensus::{ConsensusKeyRecord, ConsensusKeyStatus},
    da::commitment::DaProofPolicyBundle,
    isi::{
        GrantBox, RegisterBox, RevokeBox, SetAssetDefinitionAlias,
        alias_setup::EnsureAlias,
        consensus_keys::RegisterConsensusKey,
        nexus::{
            ActivateFeeSponsorProgramRevision, CreateFeeSponsorProgram,
            EnrollFeeSponsorBeneficiary, FundFeeSponsorProgram, StageFeeSponsorProgramRevision,
        },
        space_directory::PublishSpaceDirectoryManifest,
        staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
        verifying_keys,
    },
    nexus::{
        FeeSponsorAssetBudget, FeeSponsorEligibility, FeeSponsorNativeInstructionSelector,
        FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramRevision, FeeSponsorRule,
        FeeSponsorRuleEffect, FeeSponsorRuleSelector, PublicLaneMonetaryPlanV1,
    },
    parameter::{
        custom::{CustomParameter, CustomParameterId},
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    },
    prelude::*,
    private_dataspace::PrivateDataspaceAdmissionPolicy,
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
};
use iroha_executor_data_model::permission::{
    account::{
        AccountAliasPermissionScope, CanManageAccountAlias, CanRegisterAccount,
        CanResolveAccountAlias,
    },
    governance::{CanEnactGovernance, CanManageConsensusKeys},
    nexus::{
        CanEnrollFeeSponsorProgram, CanPublishSpaceDirectoryManifest,
        CanPublishSpaceDirectoryManifestForAccountDomain,
    },
    parameter::{CanSetHijiriParameters, CanSetParameters},
    query::{CanReadAllLedgerData, CanReadRestrictedDataspace},
    smart_contract::{CanGrantSmartContractCodeManagement, CanManageSmartContractCode},
};
use iroha_genesis::{
    GenesisBuilder, GenesisTopologyEntry, RawGenesisTransaction, SIGNED_GENESIS_MAX_BYTES_V1,
    init_instruction_registry, read_signed_genesis, validate_genesis_manifest_json,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::DataSpaceId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::addr::{SocketAddr, SocketAddrHost};
use iroha_primitives::json::Json;
use iroha_primitives::numeric::{Numeric, Quantity};
#[cfg(test)]
use iroha_test_samples::{ALICE_ID, REAL_GENESIS_ACCOUNT_KEYPAIR};
use rand::{TryRngCore as _, rngs::OsRng};
pub use service_authorities::LocalnetServiceProfile;
use std::{
    collections::BTreeSet,
    env, fs,
    io::{BufWriter, Write},
    net::{Ipv4Addr, Ipv6Addr},
    num::{NonZeroU16, NonZeroU64},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize as _, Zeroizing};

mod managed_puzzle;
mod private_root;
pub(crate) use custody::sync_private_tree;
pub(crate) use private_root::private_fee_policy;
pub use private_root::{PrivateRootSpec, prepare_private_root};
pub(crate) use private_root::{
    prepare_private_root_at, prepare_private_root_with_amx_at,
    verify_retained as verify_private_root,
};

/// User-facing options for generating a bare-metal localnet.
pub struct LocalnetOptions {
    /// Closed service-authority preparation; token services remain disabled.
    pub service_profile: LocalnetServiceProfile,
    /// Optional Sora profile selector (multi-lane / dataspace defaults).
    pub sora_profile: Option<SoraProfile>,
    /// Optional localnet performance profile (throughput presets).
    pub perf_profile: Option<LocalnetPerfProfile>,
    /// Number of peers to create (deterministic ordering, minimum four).
    pub peers: NonZeroU16,
    /// Optional seed to make key/port generation reproducible.
    pub seed: Option<String>,
    /// Host interface to bind P2P and Torii listeners to (host/IP only, no port).
    pub bind_host: String,
    /// Host peers should gossip to and clients should dial (host/IP only, no port).
    pub public_host: String,
    /// Base Torii API port; each peer increments this by one.
    pub base_api_port: u16,
    /// Base P2P port; each peer increments this by one.
    pub base_p2p_port: u16,
    /// Output directory for configs, scripts, and genesis.
    pub out_dir: PathBuf,
    /// Additional wonderland accounts to pre-register beyond Alice.
    pub extra_accounts: u16,
    /// Additional asset specs to register and optionally mint on top of the built-in localnet asset set.
    pub assets: Vec<AssetSpec>,
    /// Optional signed-genesis block cadence override in milliseconds.
    /// If unset, localnet uses a one-second cadence.
    pub block_cadence_ms: Option<u64>,
    /// Consensus mode to commit in signed genesis.
    pub consensus_mode: SumeragiConsensusMode,
}
impl Drop for LocalnetOptions {
    fn drop(&mut self) {
        if let Some(seed) = self.seed.as_mut() {
            seed.zeroize();
        }
    }
}
/// Asset definition plus optional minting target for sample generation.
#[derive(Debug, Clone)]
pub struct AssetSpec {
    /// Canonical asset definition ID (unprefixed Base58 address).
    pub id: String,
    /// Human-readable display name for the asset definition.
    pub name: String,
    /// Optional leased alias binding to attach after registration.
    pub alias: Option<String>,
    /// Account that should own the asset definition after genesis completes.
    pub owned_by: AccountId,
    /// Account that should receive the minted supply.
    pub mint_to: AccountId,
    /// Quantity to mint for this asset definition.
    pub quantity: u64,
}
#[derive(Debug, Clone)]
enum HostKind {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Name(String),
}
#[derive(Debug, Clone)]
struct CanonicalHost {
    kind: HostKind,
}
impl CanonicalHost {
    fn parse(raw: &str, field: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(eyre!("`{field}` must not be empty"));
        }
        if trimmed != raw {
            return Err(eyre!("`{field}` must not contain surrounding whitespace"));
        }
        let has_prefix = trimmed.starts_with('[');
        let has_suffix = trimmed.ends_with(']');
        if has_prefix != has_suffix {
            return Err(eyre!("`{field}` has unmatched '[' or ']': `{raw}`"));
        }
        let unbracketed = if has_prefix && trimmed.len() >= 2 {
            &trimmed[1..trimmed.len() - 1]
        } else {
            trimmed
        };
        if unbracketed.is_empty() {
            return Err(eyre!("`{field}` must not be empty"));
        }
        if has_prefix {
            return unbracketed.parse::<Ipv6Addr>().map_or_else(
                |_| {
                    Err(eyre!(
                        "`{field}` brackets are only valid around an IPv6 literal"
                    ))
                },
                |ipv6| {
                    Ok(Self {
                        kind: HostKind::Ipv6(ipv6),
                    })
                },
            );
        }
        if let Ok(ipv4) = unbracketed.parse::<Ipv4Addr>() {
            return Ok(Self {
                kind: HostKind::Ipv4(ipv4),
            });
        }
        if let Ok(ipv6) = unbracketed.parse::<Ipv6Addr>() {
            return Ok(Self {
                kind: HostKind::Ipv6(ipv6),
            });
        }
        if unbracketed.contains(':') {
            return Err(eyre!(
                "`{field}` must be a host name or IP literal without a port: `{raw}`"
            ));
        }
        if unbracketed.len() > 253
            || !unbracketed.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(eyre!(
                "`{field}` must be an ASCII DNS name or IP literal without a port: `{raw}`"
            ));
        }
        Ok(Self {
            kind: HostKind::Name(unbracketed.to_ascii_lowercase()),
        })
    }
    fn addr_literal(&self, port: u16) -> String {
        let addr = match &self.kind {
            HostKind::Ipv4(ipv4) => SocketAddr::from((ipv4.octets(), port)),
            HostKind::Ipv6(ipv6) => SocketAddr::from((ipv6.segments(), port)),
            HostKind::Name(host) => SocketAddr::Host(SocketAddrHost {
                host: host.clone().into(),
                port,
            }),
        };
        addr.to_literal()
    }
    fn url_host(&self) -> String {
        match &self.kind {
            HostKind::Ipv4(ipv4) => ipv4.to_string(),
            HostKind::Ipv6(ipv6) => format!("[{ipv6}]"),
            HostKind::Name(host) => host.clone(),
        }
    }
    fn torii_url(&self, port: u16) -> String {
        format!("http://{}:{port}/", self.url_host())
    }
}

/// Validate and canonicalize a host name or IP literal for another Kagami command.
pub fn canonical_host(raw: &str, field: &str) -> Result<String> {
    Ok(CanonicalHost::parse(raw, field)?.url_host())
}

/// Validate a non-zero endpoint and render its canonical socket-address literal.
pub fn canonical_endpoint_literal(raw: &str, field: &str, port: u16) -> Result<String> {
    ensure!(port != 0, "`{field}` port must be greater than zero");
    Ok(CanonicalHost::parse(raw, field)?.addr_literal(port))
}
/// SORA network profiles that influence localnet defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoraProfile {
    /// Dataspace-oriented defaults.
    Dataspace,
    /// State Bank of Pakistan restricted dataspace defaults.
    PrivateSbp,
    /// Central Bank of the UAE restricted dataspace defaults.
    PrivateCbuae,
    /// Bank of Papua New Guinea restricted local dataspace defaults.
    PrivateBpng,
    /// Public dataspace (Nexus) defaults.
    Nexus,
}
impl SoraProfile {
    fn consensus_policy(self) -> ConsensusPolicy {
        match self {
            SoraProfile::Dataspace
            | SoraProfile::PrivateSbp
            | SoraProfile::PrivateCbuae
            | SoraProfile::PrivateBpng
            | SoraProfile::Nexus => ConsensusPolicy::PublicDataspace,
        }
    }
}
/// Localnet performance profiles for 10k TPS / 1s finality runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalnetPerfProfile {
    /// 10k TPS / 1s finality baseline for permissioned mode.
    Throughput10kPermissioned,
    /// 10k TPS / 1s finality baseline for NPoS mode.
    Throughput10kNpos,
}
#[derive(Debug, Clone, Copy)]
struct LocalnetPerfProfileSpec {
    consensus_mode: SumeragiConsensusMode,
    block_cadence_ms: u64,
    block_max_transactions: u64,
    stake_amount: u64,
}
impl LocalnetPerfProfile {
    fn spec(self) -> LocalnetPerfProfileSpec {
        let consensus_mode = match self {
            LocalnetPerfProfile::Throughput10kPermissioned => SumeragiConsensusMode::Permissioned,
            LocalnetPerfProfile::Throughput10kNpos => SumeragiConsensusMode::Npos,
        };
        LocalnetPerfProfileSpec {
            consensus_mode,
            block_cadence_ms: 1_000,
            block_max_transactions: LOCALNET_BLOCK_MAX_TRANSACTIONS,
            stake_amount: LOCALNET_STAKE_AMOUNT,
        }
    }
    /// Consensus mode required by this throughput preset.
    pub fn consensus_mode(self) -> SumeragiConsensusMode {
        self.spec().consensus_mode
    }
}
/// Stable command and configuration spelling of a consensus mode.
pub fn consensus_mode_label(mode: SumeragiConsensusMode) -> &'static str {
    match mode {
        SumeragiConsensusMode::Permissioned => "permissioned",
        SumeragiConsensusMode::Npos => "npos",
    }
}
/// Default chain label for independently identified disposable localnets.
pub const DEFAULT_CHAIN_ID: &str = "00000000-0000-0000-0000-000000000000";
const TAIRA_TESTNET_PEERS: u16 = 4;
const TAIRA_SORACLOUD_HYDRATION_CONCURRENCY: i64 = taira_defaults::HYDRATION_CONCURRENCY as i64;
const TAIRA_SORACLOUD_PREPARED_RUNTIME_CACHE_CAPACITY: i64 =
    taira_defaults::PREPARED_RUNTIME_CACHE_CAPACITY as i64;
const TAIRA_RUNTIME_SIGNER_SEED_DOMAIN: &[u8] = b"iroha:kagami:taira:runtime-signer:v1|";
const TAIRA_RUNTIME_SIGNER_REVISION: u64 = 1;
const TAIRA_RUNTIME_SIGNER_POLICY_DIGEST_DOMAIN: &[u8] =
    b"iroha.taira.runtime-signer.compiled-policy.digest.v1\0";
const TAIRA_RUNTIME_SIGNER_COMPILED_POLICY: &[u8] = b"algorithm=ed25519;credential=inherited-fd-198-consumed-after-load;descriptor=stable-owner-euid-regular-mode-0600-nlink-1-size-71;key=canonical-private-multihash-plus-newline;handle=software://taira/inrou/<lowercase-raw-public-key-hex>;authority=account-id(public-key);transactions=exact-authority-payload;provenance=canonical-soracloud-v1-domain-version-purpose-preimage;qualification=active-nontest;";
const TAIRA_RUNTIME_SIGNER_HANDLE_PREFIX: &str = "software://taira/inrou/";
const TAIRA_RUNTIME_SIGNER_DIRECTORY: &str = "taira-runtime-signers";

fn taira_runtime_signer_policy_digest() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TAIRA_RUNTIME_SIGNER_POLICY_DIGEST_DOMAIN);
    hasher.update(&TAIRA_RUNTIME_SIGNER_REVISION.to_be_bytes());
    hasher.update(
        &u64::try_from(TAIRA_RUNTIME_SIGNER_COMPILED_POLICY.len())
            .expect("compiled Taira signer policy length fits u64")
            .to_be_bytes(),
    );
    hasher.update(TAIRA_RUNTIME_SIGNER_COMPILED_POLICY);
    *hasher.finalize().as_bytes()
}

/// Domain-separation label for an explicitly seeded development genesis key.
pub const GENESIS_SEED: &[u8; 7] = b"genesis";
const SORANET_TRANSPORT_SEED_DOMAIN: &[u8] = b"iroha:kagami:localnet:soranet-transport:v1|";
const STREAMING_IDENTITY_SEED_DOMAIN: &[u8] = b"iroha:kagami:localnet:streaming-identity:v1|";
/// Total P2P connection bound: the other validators in the largest committee
/// plus two authenticated observer connections.
const LOCALNET_MAX_TOTAL_CONNECTIONS: usize = MAX_VALIDATORS_PER_HEIGHT - 1 + 2;
/// Capacity for the inbound P2P subscriber queue in localnet configs.
const LOCALNET_P2P_SUBSCRIBER_QUEUE_CAP: usize = 16_384;
/// Default consensus ingress rate cap (msgs/sec) for localnet.
const LOCALNET_CONSENSUS_INGRESS_RATE_PER_SEC: u32 = 600;
/// Default consensus ingress burst cap (msgs) for localnet.
const LOCALNET_CONSENSUS_INGRESS_BURST: u32 = 600;
/// Default consensus ingress bytes/sec cap for localnet.
const LOCALNET_CONSENSUS_INGRESS_BYTES_PER_SEC: u32 = 134_217_728; // 128 MiB
/// Default consensus ingress bytes burst cap for localnet.
const LOCALNET_CONSENSUS_INGRESS_BYTES_BURST: u32 = 268_435_456; // 256 MiB
/// Default critical consensus ingress rate cap (msgs/sec) for localnet.
const LOCALNET_CONSENSUS_INGRESS_CRITICAL_RATE_PER_SEC: u32 = 600;
/// Default critical consensus ingress burst cap (msgs) for localnet.
const LOCALNET_CONSENSUS_INGRESS_CRITICAL_BURST: u32 = 600;
/// Default critical consensus ingress bytes/sec cap for localnet.
const LOCALNET_CONSENSUS_INGRESS_CRITICAL_BYTES_PER_SEC: u32 = 268_435_456; // 256 MiB
/// Default critical consensus ingress bytes burst cap for localnet.
const LOCALNET_CONSENSUS_INGRESS_CRITICAL_BYTES_BURST: u32 = 536_870_912; // 512 MiB
/// Transaction gossip cadence for 1s localnet pipelines (ms).
const LOCALNET_TX_GOSSIP_PERIOD_FAST_MS: u64 = 100;
/// Transaction gossip resend ticks for 1s localnet pipelines.
const LOCALNET_TX_GOSSIP_RESEND_TICKS_FAST: u32 = 1;
/// Tx gossip frame cap for localnets so large public transactions still fit.
const LOCALNET_MAX_FRAME_BYTES_TX_GOSSIP_NEXUS: usize = 1_048_576;
/// Base P2P frame cap for generated localnets.
///
/// Localnets use the production 17 MiB cap because certified-body recovery can
/// carry the full recommended 16 MiB payload plus its manifest, relay wrapper,
/// and AEAD overhead. A smaller development-only cap can deadlock block sync.
const LOCALNET_MAX_FRAME_BYTES: usize =
    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES.get();
/// Consensus message frame cap for generated localnets.
const LOCALNET_MAX_FRAME_BYTES_CONSENSUS: usize =
    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONSENSUS.get();
/// Block-sync frame cap for generated localnets.
const LOCALNET_MAX_FRAME_BYTES_BLOCK_SYNC: usize =
    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_BLOCK_SYNC.get();
/// Control-message frame cap for generated localnets.
///
/// This carries maximal consensus-safety proposals and timeout certificates.
const LOCALNET_MAX_FRAME_BYTES_CONTROL: usize =
    iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONTROL.get();
/// Peer-gossip frame cap for generated localnets.
const LOCALNET_MAX_FRAME_BYTES_PEER_GOSSIP: usize = 65_536;
/// Health-check frame cap for generated localnets.
const LOCALNET_MAX_FRAME_BYTES_HEALTH: usize = 32_768;
/// Miscellaneous frame cap for generated localnets.
const LOCALNET_MAX_FRAME_BYTES_OTHER: usize = 131_072;
/// Default listener host for generated P2P and Torii services.
pub const DEFAULT_BIND_HOST: &str = "0.0.0.0";
/// Default advertised host for generated peers and client config.
pub const DEFAULT_PUBLIC_HOST: &str = "127.0.0.1";
/// Default total pipeline time (ms) injected for localnet when not overridden.
const LOCALNET_PIPELINE_TIME_MS: u64 = 1_000;
/// Default queue capacity for localnet (safe-by-default).
///
/// This value intentionally trades peak stress throughput for bounded memory
/// usage when consensus stalls or clients oversubmit.
const LOCALNET_QUEUE_CAPACITY: usize = 20_000;
/// Queue capacity used for perf-profile localnets.
///
/// The queue also enforces a retained-byte budget, which is the binding limit for
/// high-throughput localnet bursts. Keep the count cap only high enough to avoid
/// count-based rejection before the byte guard engages; larger values preallocate
/// fixed queue slots that sit mostly empty under the byte budget.
const LOCALNET_PERF_QUEUE_CAPACITY: usize = 4_096;
/// Default transaction TTL in the queue for localnet (ms).
const LOCALNET_QUEUE_TTL_MS: u64 = 600_000;
/// Default lane TEU capacity for localnet scheduling (raises per-block budget).
const LOCALNET_LANE_TEU_CAPACITY: u32 = 50_000_000;
/// Default IVM gas budget per block for Taira/localnet stress profiles.
const LOCALNET_IVM_GAS_LIMIT_PER_BLOCK: u64 = 50_000_000;
/// Default IVM gas price for localnet fee assets.
const LOCALNET_IVM_GAS_UNITS_PER_GAS: u64 = 1;
/// Default Torii tx rate limit (per authority) for localnet.
const LOCALNET_TORII_TX_RATE_PER_AUTHORITY_PER_SEC: u32 =
    iroha_config::parameters::defaults::torii::DEFAULT_REQUEST_RATE_PER_SEC;
/// Default Torii tx burst limit (per authority) for localnet.
const LOCALNET_TORII_TX_BURST_PER_AUTHORITY: u32 =
    iroha_config::parameters::defaults::torii::DEFAULT_REQUEST_BURST;
/// Default Torii pre-auth rate limit (per IP) for localnet.
const LOCALNET_TORII_PREAUTH_RATE_PER_IP_PER_SEC: u32 =
    iroha_config::parameters::defaults::torii::DEFAULT_REQUEST_RATE_PER_SEC;
/// Default Torii pre-auth burst limit (per IP) for localnet.
const LOCALNET_TORII_PREAUTH_BURST_PER_IP: u32 =
    iroha_config::parameters::defaults::torii::DEFAULT_REQUEST_BURST;
/// Torii request body cap emitted explicitly in localnet configs.
const LOCALNET_TORII_MAX_CONTENT_LEN: u64 =
    iroha_config::parameters::defaults::torii::MAX_CONTENT_LEN.0;
/// Torii pre-auth allowlist to keep localnet CLI traffic from tripping bans.
const LOCALNET_PREAUTH_ALLOW_CIDRS: [&str; 2] = ["127.0.0.0/8", "::1/128"];
/// Exact Torii transport sources trusted for internal localnet reads and routing.
const LOCALNET_INTERNAL_API_TRUSTED_CIDRS: [&str; 2] = ["127.0.0.1/32", "::1/128"];
/// Telemetry profile generated for localnet peers.
const LOCALNET_TELEMETRY_PROFILE: &str = "extended";
/// Minimum peer count for generated localnets.
const LOCALNET_MIN_PEERS: u16 = 4;
/// Divisor applied to derive the localnet NPoS aggregator fallback timeout.
/// Keep this at 1 so aggregators do not time out before quorum on fast pipelines.
/// Default max transactions per block for localnet (targets 10k TPS).
const LOCALNET_BLOCK_MAX_TRANSACTIONS: u64 = 10_000;
/// Default stake bonded per localnet validator (raised to meet min_self_bond).
const LOCALNET_STAKE_AMOUNT: u64 = 10_000;
const LOCALNET_FAUCET_AUTHORITY_BALANCE: u64 = 1_000_000_000;
const LOCALNET_FEE_SPONSOR_PROGRAM_NAME: &str = "default";
const LOCALNET_FEE_SPONSOR_VAULT_BALANCE: u64 = 100_000_000;
const LOCALNET_FEE_SPONSOR_PER_TRANSACTION: u64 = 1_000_000;
const LOCALNET_FEE_SPONSOR_PER_BLOCK: u64 = 10_000_000;
const LOCALNET_FEE_SPONSOR_PER_PROGRAM_EPOCH: u64 = 100_000_000;
const LOCALNET_FEE_SPONSOR_PER_BENEFICIARY_EPOCH: u64 = 50_000_000;
const LOCALNET_FEE_SPONSOR_RESERVE_FLOOR: u64 = 10_000_000;
const LOCALNET_FEE_SPONSOR_EPOCH_BLOCKS: u64 = 3_600;
const LOCALNET_ONBOARDING_CREDENTIAL_ID: &str = "local-dev";
const LOCALNET_OPERATOR_ALIAS: &str = "operator@wonderland.universal";
const TAIRA_LOCALNET_OPERATOR_ALIAS: &str = "operator@taira.universal";
const TAIRA_CANARY_DOMAIN: &str = "taira.universal";
const TAIRA_CANARY_DATASPACE_ALIAS: &str = "universal";
const LOCALNET_ALIAS_SETUP_INTENT_FILE: &str = "alias-setup.intent.json";
const LOCALNET_ALIAS_SETUP_PAYER_BALANCE: u64 = 10;
const LOCALNET_ALIAS_SETUP_POLICY_VERSION: u16 = 1;
const LOCALNET_RUNTIME_DIRECTORY: &str = "runtime";
const LOCALNET_OPERATOR_SIGNER_KEY_FILE: &str = "operator-signer.key";
const LOCALNET_LEDGER_SIGNER_KEY_FILE: &str = "ledger-signer.key";
const LOCALNET_ONBOARDING_SIGNER_KEY_FILE: &str = "onboarding-signer.key";
const LOCALNET_ONBOARDING_TOKEN_FILE: &str = "onboarding.token";
const LOCALNET_FAUCET_AMOUNT: &str = "25000";
const LOCALNET_FAUCET_POW_DIFFICULTY_BITS: i64 = 8;
const LOCALNET_FAUCET_POW_SCRYPT_LOG_N: i64 = 13;
const LOCALNET_FAUCET_POW_SCRYPT_R: i64 = 8;
const LOCALNET_FAUCET_POW_SCRYPT_P: i64 = 1;
const LOCALNET_FAUCET_POW_MAX_ANCHOR_AGE_BLOCKS: i64 = 6;
const LOCALNET_FAUCET_POW_ADAPTIVE_LOOKBACK_BLOCKS: i64 = 64;
const LOCALNET_FAUCET_POW_ADAPTIVE_CLAIMS_PER_EXTRA_BIT: i64 = 4;
const LOCALNET_FAUCET_POW_ADAPTIVE_MAX_EXTRA_BITS: i64 = 2;
const LOCALNET_PRIVATE_SNS_LEASE_PAYMENT: &str = "0.5";
const LOCALNET_NEXUS_DOMAIN: &str = "nexus.universal";
const LOCALNET_IVM_DOMAIN: &str = "ivm.universal";
const LOCALNET_UNIVERSAL_DOMAIN: &str = "universal.universal";
const LOCALNET_SAMPLE_ASSET_DOMAIN: &str = "wonderland.universal";
/// Name of the optional developer sample asset.
pub const LOCALNET_SAMPLE_ASSET_NAME: &str = "sample";
const LOCALNET_REQUESTED_ASSET_INITIAL_QUANTITY: u64 = 1_000_000_000;
const LOCALNET_BPNG_DATASPACE_ID: u64 = 8_648_377_547_929_788_715;
/// Isolated private-BPNG localnet placement, matching the public Taira BPNG lane.
const LOCALNET_BPNG_LANE_INDEX: u32 = 5;
/// Fresh SORA Taira catalog: universal lanes 0-2 plus one lane per participant dataspace.
const TAIRA_LANE_COUNT: i64 = 8;
/// How one fresh SORA Taira participant lane admits its validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TairaLaneAdmission {
    /// Open lane served by its own stake-elected public validator pool.
    Public,
    /// Restricted lane governed by its authenticated Parliament lane manifest.
    Restricted,
}
/// One fresh SORA Taira participant dataspace and its single dedicated lane.
///
/// The lane alias equals the dataspace alias, and the dataspace identity is the full SNS
/// dataspace-alias name hash, so no numeric identifier is configured.
#[derive(Debug, Clone, Copy)]
struct TairaParticipantLane {
    alias: &'static str,
    lane_index: u32,
    admission: TairaLaneAdmission,
    /// Route account traffic scoped exactly to this dataspace (`*@<alias>`) to this lane.
    account_route: bool,
    dataspace_description: &'static str,
    lane_description: &'static str,
}
impl TairaParticipantLane {
    /// Full SNS dataspace-alias name hash, used verbatim as the catalog `manifest_hash`.
    fn manifest_hash(self) -> [u8; 32] {
        NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, self.alias)
            .expect("static Taira dataspace alias must be a canonical SNS label")
            .name_hash()
    }
    fn dataspace_id(self) -> DataSpaceId {
        DataSpaceId::from_hash(&self.manifest_hash())
    }
    fn restricted(self) -> bool {
        self.admission == TairaLaneAdmission::Restricted
    }
}
/// Fresh SORA Taira participant lanes in lane-index order.
const TAIRA_PARTICIPANT_LANES: [TairaParticipantLane; 5] = [
    TairaParticipantLane {
        alias: "dpn",
        lane_index: 3,
        admission: TairaLaneAdmission::Restricted,
        account_route: true,
        dataspace_description: "Digital payments network restricted dataspace",
        lane_description: "Digital payments network restricted lane",
    },
    TairaParticipantLane {
        alias: "is2",
        lane_index: 4,
        admission: TairaLaneAdmission::Restricted,
        account_route: true,
        dataspace_description: "Bank of Israel mobile-wallet restricted dataspace",
        lane_description: "Bank of Israel mobile-wallet restricted lane",
    },
    // BPNG is public: it has no manifest or account route, and its traffic routes by target
    // dataspace to its own stake-elected validator pool.
    TairaParticipantLane {
        alias: "bpng",
        lane_index: LOCALNET_BPNG_LANE_INDEX,
        admission: TairaLaneAdmission::Public,
        account_route: false,
        dataspace_description: "Bank of Papua New Guinea public dataspace",
        lane_description: "Bank of Papua New Guinea public lane",
    },
    TairaParticipantLane {
        alias: "cbsi",
        lane_index: 6,
        admission: TairaLaneAdmission::Restricted,
        account_route: true,
        dataspace_description: "Central-bank service integration restricted dataspace",
        lane_description: "Central-bank service integration restricted lane",
    },
    TairaParticipantLane {
        alias: "is",
        lane_index: 7,
        admission: TairaLaneAdmission::Restricted,
        account_route: true,
        dataspace_description: "External proof-of-concept restricted dataspace",
        lane_description: "External proof-of-concept restricted lane",
    },
];
const LOCALNET_GAS_ACCOUNT_DOMAIN: &[u8] = b"iroha:localnet:gas-custody:v1";
/// Default localnet client TTL (ms) to keep stress submissions from expiring prematurely.
const LOCALNET_CLIENT_TTL_MS: u64 = 600_000;
/// Default localnet client status timeout (ms); must stay <= TTL.
const LOCALNET_CLIENT_STATUS_TIMEOUT_MS: u64 = 300_000;
/// Default Kura fsync mode for localnet (performance-oriented).
const LOCALNET_KURA_FSYNC_MODE: &str = "batched";
/// Directory of a localnet peer's Sumeragi safety records, under its state root.
const LOCALNET_SUMERAGI_RECORDS_DIR: &str = "sumeragi-records";
/// A localnet peer's Sumeragi key installation log, under its state root.
const LOCALNET_SUMERAGI_INSTALLATION_LOG: &str = "sumeragi-installation.log";
/// Aggregate Nexus storage cap for each disposable localnet peer (1 GiB).
///
/// Production nodes derive a filesystem-aware budget with reserved headroom. A generated
/// localnet owns short-lived storage under its output directory, so an explicit small cap avoids
/// applying that host-wide production policy to a throwaway network.
const LOCALNET_NEXUS_STORAGE_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;
/// Exact first-release Taira Nexus storage weights, in basis points.
const TAIRA_NEXUS_STORAGE_WEIGHTS: [(&str, u16); 3] = [
    ("kura_blocks_bps", taira_defaults::NEXUS_KURA_BLOCKS_BPS),
    ("wsv_snapshots_bps", taira_defaults::NEXUS_WSV_SNAPSHOTS_BPS),
    ("sorafs_bps", taira_defaults::NEXUS_SORAFS_BPS),
];
/// Ed25519 signature batch size for perf-profile localnets (0 disables batching).
const LOCALNET_SIGNATURE_BATCH_MAX_ED25519: usize = 64;
/// Logger filter for perf-profile localnets to avoid per-transaction log floods.
const LOCALNET_PERF_LOGGER_FILTER: &str = "info,iroha_torii::routing=warn";
const RANS_SEED0_TABLE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../codec/rans/tables/rans_seed0.toml"
));
const LOCALNET_RANS_TABLE_RELATIVE_PATH: &str = "codec/rans/tables/rans_seed0.toml";
fn localnet_dataspace_fault_tolerance(peers: NonZeroU16) -> u32 {
    let peers = u32::from(peers.get());
    let fault_tolerance = peers.saturating_sub(1) / 3;
    fault_tolerance.max(1)
}
const LOCALNET_PAYNET_ALIAS_DATASPACE_ID: u64 = 10;
const LOCALNET_CBUAE_ALIAS_DATASPACE_ID: u64 = 12;
const LOCALNET_PAYNET_ALIAS_LANE_INDEX: u32 = 3;
const LOCALNET_CBUAE_ALIAS_LANE_INDEX: u32 = 4;
const LOCALNET_NEXUS_ALIAS_LANE_COUNT: i64 = 5;
#[cfg(test)]
const LOCALNET_PAYNET_ALIAS_LANE_COUNT: i64 = 4;
#[derive(Debug, Clone, Copy)]
struct PrivateDataspaceRoute {
    matcher: &'static str,
    description: &'static str,
}
#[derive(Debug, Clone, Copy)]
struct PrivateDataspaceSpec {
    alias: &'static str,
    id: u64,
    lane_index: u32,
    dataspace_description: &'static str,
    lane_description: &'static str,
    account_routes: &'static [PrivateDataspaceRoute],
    transfer_routes: &'static [PrivateDataspaceRoute],
}
const PAYNET_ACCOUNT_ROUTES: &[PrivateDataspaceRoute] = &[
    PrivateDataspaceRoute {
        matcher: "*@paynet",
        description: "Route *@paynet account traffic to paynet lane",
    },
    PrivateDataspaceRoute {
        matcher: "*@mibank.paynet",
        description: "Route *@mibank.paynet account traffic to paynet lane",
    },
];
const SBP_ACCOUNT_ROUTES: &[PrivateDataspaceRoute] = &[
    PrivateDataspaceRoute {
        matcher: "*@sbp",
        description: "Route SBP authority traffic to the SBP lane",
    },
    PrivateDataspaceRoute {
        matcher: "*@hbl.sbp",
        description: "Route HBL alias-scope traffic inside the SBP dataspace to the SBP lane",
    },
    PrivateDataspaceRoute {
        matcher: "*@ubl.sbp",
        description: "Route UBL alias-scope traffic inside the SBP dataspace to the SBP lane",
    },
];
const SBP_TRANSFER_ROUTES: &[PrivateDataspaceRoute] = &[
    PrivateDataspaceRoute {
        matcher: "transfer::asset@sbp",
        description: "Route transfer destination alias scope sbp to the SBP lane",
    },
    PrivateDataspaceRoute {
        matcher: "transfer::asset@hbl.sbp",
        description: "Route transfer destination alias scope hbl.sbp inside the SBP dataspace to the SBP lane",
    },
    PrivateDataspaceRoute {
        matcher: "transfer::asset@ubl.sbp",
        description: "Route transfer destination alias scope ubl.sbp inside the SBP dataspace to the SBP lane",
    },
];
const CBUAE_ACCOUNT_ROUTES: &[PrivateDataspaceRoute] = &[PrivateDataspaceRoute {
    matcher: "*@cbuae",
    description: "Route CBUAE authority traffic to the CBUAE lane",
}];
const CBUAE_TRANSFER_ROUTES: &[PrivateDataspaceRoute] = &[PrivateDataspaceRoute {
    matcher: "transfer::asset@cbuae",
    description: "Route transfer destination alias scope cbuae to the CBUAE lane",
}];
const BPNG_ACCOUNT_ROUTES: &[PrivateDataspaceRoute] = &[
    PrivateDataspaceRoute {
        matcher: "*@bpng",
        description: "Route BPNG authority traffic to the BPNG lane",
    },
    PrivateDataspaceRoute {
        matcher: "*@mibank.bpng",
        description: "Route MiBank alias-scope traffic inside the BPNG dataspace to the BPNG lane",
    },
];
const BPNG_TRANSFER_ROUTES: &[PrivateDataspaceRoute] = &[
    PrivateDataspaceRoute {
        matcher: "transfer::asset@bpng",
        description: "Route transfer destination alias scope bpng to the BPNG lane",
    },
    PrivateDataspaceRoute {
        matcher: "transfer::asset@mibank.bpng",
        description: "Route transfer destination alias scope mibank.bpng inside the BPNG dataspace to the BPNG lane",
    },
];
const SBP_BOOTSTRAP_DOMAINS: &[&str] = &["hbl.sbp", "ubl.sbp"];
const BPNG_BOOTSTRAP_DOMAINS: &[&str] = &["mibank.bpng"];
fn private_dataspace_spec(sora_profile: Option<SoraProfile>) -> Option<PrivateDataspaceSpec> {
    match sora_profile? {
        SoraProfile::Dataspace => Some(PrivateDataspaceSpec {
            alias: "paynet",
            id: LOCALNET_PAYNET_ALIAS_DATASPACE_ID,
            lane_index: LOCALNET_PAYNET_ALIAS_LANE_INDEX,
            dataspace_description: "Private central-bank digital-currency dataspace",
            lane_description: "Private central-bank digital-currency dataspace lane",
            account_routes: PAYNET_ACCOUNT_ROUTES,
            transfer_routes: &[],
        }),
        SoraProfile::PrivateSbp => Some(PrivateDataspaceSpec {
            alias: "sbp",
            id: LOCALNET_PAYNET_ALIAS_DATASPACE_ID,
            lane_index: LOCALNET_PAYNET_ALIAS_LANE_INDEX,
            dataspace_description: "State Bank of Pakistan dataspace",
            lane_description: "State Bank of Pakistan private lane",
            account_routes: SBP_ACCOUNT_ROUTES,
            transfer_routes: SBP_TRANSFER_ROUTES,
        }),
        SoraProfile::PrivateCbuae => Some(PrivateDataspaceSpec {
            alias: "cbuae",
            id: LOCALNET_CBUAE_ALIAS_DATASPACE_ID,
            lane_index: LOCALNET_CBUAE_ALIAS_LANE_INDEX,
            dataspace_description: "CBUAE dataspace",
            lane_description: "CBUAE private lane",
            account_routes: CBUAE_ACCOUNT_ROUTES,
            transfer_routes: CBUAE_TRANSFER_ROUTES,
        }),
        SoraProfile::PrivateBpng => Some(PrivateDataspaceSpec {
            alias: "bpng",
            id: LOCALNET_BPNG_DATASPACE_ID,
            lane_index: LOCALNET_BPNG_LANE_INDEX,
            dataspace_description: "Bank of Papua New Guinea dataspace",
            lane_description: "Bank of Papua New Guinea private lane",
            account_routes: BPNG_ACCOUNT_ROUTES,
            transfer_routes: BPNG_TRANSFER_ROUTES,
        }),
        SoraProfile::Nexus => None,
    }
}
fn localnet_uses_alias_multilane_catalog(sora_profile: Option<SoraProfile>) -> bool {
    matches!(
        sora_profile,
        Some(
            SoraProfile::Nexus
                | SoraProfile::Dataspace
                | SoraProfile::PrivateSbp
                | SoraProfile::PrivateCbuae
                | SoraProfile::PrivateBpng
        )
    )
}
fn canonical_asset_definition_id(domain: &str, name: &str) -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::parse_fully_qualified(domain)
            .expect("static asset definition domain must remain valid"),
        name.parse()
            .expect("static asset definition name must remain valid"),
    )
}
/// Derive the canonical definition address for a fully qualified domain and asset name.
pub fn canonical_asset_definition_literal(domain: &str, name: &str) -> String {
    canonical_asset_definition_id(domain, name).canonical_address()
}
pub(crate) fn localnet_xor_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(TAIRA_XOR_ASSET_DEFINITION_ID)
        .expect("canonical isolated-network XOR definition")
}
fn localnet_xor_asset_literal() -> String {
    localnet_xor_asset_definition_id().to_string()
}
fn localnet_fee_sponsor_program_id(sponsor: &AccountId) -> FeeSponsorProgramId {
    FeeSponsorProgramId::new(
        sponsor.clone(),
        LOCALNET_FEE_SPONSOR_PROGRAM_NAME
            .parse()
            .expect("static localnet fee sponsor program name must parse"),
    )
}
fn localnet_fee_sponsor_revision(
    program_id: FeeSponsorProgramId,
    fee_asset_id: AssetDefinitionId,
) -> FeeSponsorProgramRevision {
    let publish_space_directory_manifest_wire_id = iroha_data_model::isi::registry::default()
        .wire_id(std::any::type_name::<PublishSpaceDirectoryManifest>())
        .expect("space-directory publication must have a registered V1 wire ID");
    let native = |wire_id: &str| {
        FeeSponsorRuleSelector::NativeInstruction(FeeSponsorNativeInstructionSelector {
            wire_id: wire_id.to_owned(),
            asset_definition_id: None,
        })
    };
    FeeSponsorProgramRevision {
        program_id,
        revision: 1,
        eligibility: FeeSponsorEligibility::EnrolledOnly,
        rules: vec![FeeSponsorRule {
            id: "onboarding"
                .parse()
                .expect("static localnet sponsor rule name must parse"),
            effect: FeeSponsorRuleEffect::Allow,
            selectors: vec![
                native(RegisterBox::WIRE_ID),
                native(GrantBox::WIRE_ID),
                native("iroha.alias.ensure"),
                native("nexus::EnrollFeeSponsorBeneficiary"),
                native(publish_space_directory_manifest_wire_id),
                native("iroha.account.alias.primary.compare_and_set"),
            ],
        }],
        asset_budgets: vec![FeeSponsorAssetBudget {
            asset_definition_id: fee_asset_id,
            per_transaction: Quantity::from(LOCALNET_FEE_SPONSOR_PER_TRANSACTION),
            per_block: Quantity::from(LOCALNET_FEE_SPONSOR_PER_BLOCK),
            per_program_epoch: Quantity::from(LOCALNET_FEE_SPONSOR_PER_PROGRAM_EPOCH),
            per_beneficiary_epoch: Quantity::from(LOCALNET_FEE_SPONSOR_PER_BENEFICIARY_EPOCH),
            reserve_floor: Quantity::from(LOCALNET_FEE_SPONSOR_RESERVE_FLOOR),
            epoch_length_blocks: NonZeroU64::new(LOCALNET_FEE_SPONSOR_EPOCH_BLOCKS)
                .expect("static sponsor epoch length must be non-zero"),
        }],
    }
}
const LOCALNET_FEE_ZK_VK_BACKEND: &str = iroha_core_zk::native_pipa_r::BACKEND;
const LOCALNET_FEE_ZK_VK_UNSHIELD_NAME: &str = "vk_unshield";
const LOCALNET_FEE_ASSET_SCALE: u32 = 9;
fn localnet_fee_vk_unshield_id() -> VerifyingKeyId {
    VerifyingKeyId::new(LOCALNET_FEE_ZK_VK_BACKEND, LOCALNET_FEE_ZK_VK_UNSHIELD_NAME)
}
fn localnet_confidential_fee_vk_record(name: &str, version: u32) -> Result<VerifyingKeyRecord> {
    match name {
        LOCALNET_FEE_ZK_VK_UNSHIELD_NAME => {
            confidential_v2::confidential_unshield_v2_vk_record(name, version)
                .map_err(|error| eyre!(error))
        }
        _ => Err(eyre!("unknown localnet confidential verifier name: {name}")),
    }
}
fn localnet_confidential_fee_vk_registrations() -> Result<[(VerifyingKeyId, VerifyingKeyRecord); 1]>
{
    Ok([(
        localnet_fee_vk_unshield_id(),
        localnet_confidential_fee_vk_record(LOCALNET_FEE_ZK_VK_UNSHIELD_NAME, 2)?,
    )])
}
/// Canonical optional sample-asset definition address.
pub fn localnet_sample_asset_literal() -> String {
    canonical_asset_definition_literal(LOCALNET_SAMPLE_ASSET_DOMAIN, LOCALNET_SAMPLE_ASSET_NAME)
}
/// Validate an explicitly requested definition and build its developer bootstrap specification.
pub fn requested_localnet_asset_spec(asset_definition_id: &str) -> Result<AssetSpec> {
    let id = asset_definition_id.trim();
    if id.is_empty() {
        return Err(eyre!("asset definition id must not be empty"));
    }
    AssetDefinitionId::parse_address_literal(id)
        .wrap_err_with(|| format!("invalid asset definition id `{id}`"))?;
    let client_account_id = localnet_client_account_id();
    Ok(AssetSpec {
        id: id.to_owned(),
        name: format!("Localnet asset {id}"),
        alias: None,
        owned_by: client_account_id.clone(),
        mint_to: client_account_id,
        quantity: LOCALNET_REQUESTED_ASSET_INITIAL_QUANTITY,
    })
}
#[cfg(test)]
fn effective_localnet_assets(extra_assets: &[AssetSpec]) -> Vec<AssetSpec> {
    effective_localnet_assets_for_client(extra_assets, &localnet_client_account_id())
}
/// Assign explicitly requested assets to the generated client. No chain, including Taira,
/// registers a built-in application asset: every asset is created after genesis.
fn effective_localnet_assets_for_client(
    extra_assets: &[AssetSpec],
    client_account_id: &AccountId,
) -> Vec<AssetSpec> {
    let default_client = localnet_client_account_id();
    extra_assets
        .iter()
        .map(|asset| {
            let mut asset = asset.clone();
            if asset.owned_by == default_client {
                asset.owned_by = client_account_id.clone();
            }
            if asset.mint_to == default_client {
                asset.mint_to = client_account_id.clone();
            }
            asset
        })
        .collect()
}

fn validate_localnet_asset_specs(extra_assets: &[AssetSpec]) -> Result<()> {
    let mut seen_asset_ids = BTreeSet::new();
    let mut seen_aliases = BTreeSet::new();
    for (index, asset) in extra_assets.iter().enumerate() {
        ensure!(
            !asset.name.trim().is_empty(),
            "localnet asset {} has an empty display name",
            index + 1
        );
        let asset_id = AssetDefinitionId::parse_address_literal(&asset.id).wrap_err_with(|| {
            format!(
                "localnet asset {} has invalid asset definition id `{}`",
                index + 1,
                asset.id
            )
        })?;
        ensure!(
            seen_asset_ids.insert(asset_id),
            "localnet asset definition id is duplicated: `{}`",
            asset.id
        );
        if let Some(alias) = asset.alias.as_deref() {
            let parsed = alias.parse::<AssetDefinitionAlias>().wrap_err_with(|| {
                format!("localnet asset {} has invalid alias `{alias}`", index + 1)
            })?;
            ensure!(
                seen_aliases.insert(parsed.to_string()),
                "localnet asset alias is duplicated: `{alias}`"
            );
        }
    }
    Ok(())
}
struct Peer {
    public_key: iroha_crypto::PublicKey,
    private_key: iroha_crypto::ExposedPrivateKey,
    soranet_transport_public_key: iroha_crypto::PublicKey,
    soranet_transport_private_key: iroha_crypto::ExposedPrivateKey,
    streaming_public_key: iroha_crypto::PublicKey,
    streaming_private_key: iroha_crypto::ExposedPrivateKey,
    bls_public_key: iroha_crypto::PublicKey,
    bls_pop: Vec<u8>,
    runtime_signer_public_key: iroha_crypto::PublicKey,
    runtime_signer_private_key: iroha_crypto::ExposedPrivateKey,
    api_port: u16,
    p2p_port: u16,
}
impl Peer {
    fn validator_account_id(&self, taira: bool) -> AccountId {
        let public_key = if taira {
            &self.runtime_signer_public_key
        } else {
            &self.public_key
        };
        AccountId::new(public_key.clone())
    }
}
struct LocalnetPeerStoragePaths {
    kura: PathBuf,
    state: PathBuf,
    soracloud_runtime: PathBuf,
    tiered_state: PathBuf,
    da_store: PathBuf,
    streaming_sessions: PathBuf,
    soranet_ticket_revocations: PathBuf,
    torii: PathBuf,
    torii_da_replay_cache: PathBuf,
    torii_da_manifests: PathBuf,
    sorafs: PathBuf,
    sorafs_por: PathBuf,
}
impl LocalnetPeerStoragePaths {
    fn new(out_dir: &Path, peer_index: usize) -> Self {
        Self::from_roots(
            out_dir.join("storage").join(format!("peer{peer_index}")),
            out_dir.join("state").join(format!("peer{peer_index}")),
        )
    }
    fn from_roots(kura: PathBuf, state: PathBuf) -> Self {
        let streaming = state.join("streaming");
        let torii = state.join("torii");
        let sorafs = state.join("sorafs");
        Self {
            kura,
            soracloud_runtime: state.join("soracloud_runtime"),
            tiered_state: state.join("tiered_state"),
            da_store: state.join("da_wsv_snapshots"),
            streaming_sessions: streaming,
            soranet_ticket_revocations: state.join("soranet").join("ticket_revocations.norito"),
            torii_da_replay_cache: torii.join("da_replay"),
            torii_da_manifests: torii.join("da_manifests"),
            torii,
            sorafs_por: sorafs.join("por"),
            sorafs,
            state,
        }
    }
}
#[derive(Debug, Clone)]
struct ResolvedHosts {
    bind: CanonicalHost,
    public: CanonicalHost,
}
#[derive(Debug, Clone)]
struct BlsEntry {
    bls_pk: String,
    pop_hex: String,
}
/// Generate a self-contained localnet: configs, genesis, client config, scripts.
///
/// # Errors
/// Returns an error if port ranges are invalid or if config, genesis, or script files cannot be written.
pub fn generate_localnet<T: Write>(
    opts: &LocalnetOptions,
    writer: &mut BufWriter<T>,
) -> Result<()> {
    generate_localnet_with_chain(opts, writer, None, None)
}
#[allow(clippy::too_many_lines)]
fn validate_localnet_options(opts: &LocalnetOptions) -> Result<ResolvedHosts> {
    validate_localnet_asset_specs(&opts.assets)?;
    if let Some(block_ms) = opts.block_cadence_ms
        && block_ms == 0
    {
        return Err(eyre!("`--block-cadence-ms` must be greater than zero"));
    }
    let validator_count = usize::from(opts.peers.get());
    if opts.peers.get() < LOCALNET_MIN_PEERS {
        return Err(eyre!(
            "`--peers` must be at least {LOCALNET_MIN_PEERS} so generated localnets exercise a representative revision-4 committee with mandatory RS16 data availability"
        ));
    }
    if validator_count > MAX_VALIDATORS_PER_HEIGHT {
        return Err(eyre!(
            "`--peers` ({validator_count}) exceeds the Sumeragi protocol maximum validator roster of {MAX_VALIDATORS_PER_HEIGHT}"
        ));
    }
    if !is_valid_committee_size(validator_count) {
        return Err(eyre!(
            "`--peers` ({validator_count}) must form an exact Sumeragi 3f+1 validator committee in the supported range 4..={MAX_VALIDATORS_PER_HEIGHT}"
        ));
    }
    if let Some(perf_spec) = opts.perf_profile.map(LocalnetPerfProfile::spec) {
        if opts.consensus_mode != perf_spec.consensus_mode {
            return Err(eyre!(
                "`--perf-profile` {:?} requires `--consensus-mode {}`",
                opts.perf_profile.expect("perf profile present"),
                match perf_spec.consensus_mode {
                    SumeragiConsensusMode::Permissioned => "permissioned",
                    SumeragiConsensusMode::Npos => "npos",
                }
            ));
        }
        if opts.sora_profile.is_some() && perf_spec.consensus_mode != SumeragiConsensusMode::Npos {
            return Err(eyre!(
                "`--perf-profile` permissioned preset cannot be combined with `--sora-profile`"
            ));
        }
    }
    if opts.sora_profile.is_some() && opts.consensus_mode != SumeragiConsensusMode::Npos {
        return Err(eyre!(
            "`--sora-profile` localnets require `--consensus-mode npos` because the global merge ledger is NPoS; use permissioned mode without `--sora-profile`"
        ));
    }
    let consensus_policy = opts
        .sora_profile
        .map_or(ConsensusPolicy::Any, SoraProfile::consensus_policy);
    validate_consensus_mode(opts.consensus_mode, consensus_policy)?;
    let bind = CanonicalHost::parse(&opts.bind_host, "--bind-host")?;
    let public = CanonicalHost::parse(&opts.public_host, "--public-host")?;
    Ok(ResolvedHosts { bind, public })
}
fn localnet_uses_npos(consensus_mode: SumeragiConsensusMode) -> bool {
    matches!(consensus_mode, SumeragiConsensusMode::Npos)
}
#[derive(Debug, Clone, Copy)]
struct LocalnetTxGossipOverrides {
    period_ms: u64,
    resend_ticks: u32,
}
/// Protocol-owned custody has no signing scalar, including when genesis is public.
fn localnet_gas_account_id(genesis_public_key: &iroha_crypto::PublicKey) -> AccountId {
    let genesis_identity = genesis_public_key.to_string();
    AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
        LOCALNET_GAS_ACCOUNT_DOMAIN,
        &[genesis_identity.as_bytes()],
    ))
}
fn account_id_raw_string(account_id: &AccountId) -> String {
    account_id.to_string()
}
fn account_id_runtime_literal(account_id: &AccountId, chain_discriminant: Option<u16>) -> String {
    chain_discriminant.map_or_else(
        || account_id_raw_string(account_id),
        |discriminant| {
            account_id
                .to_i105_for_discriminant(discriminant)
                .expect("known localnet account id must render for requested chain discriminant")
        },
    )
}
fn account_literal_for_chain_discriminant(raw: &str, chain_discriminant: u16) -> String {
    let account_id = AccountId::parse_encoded(raw).expect("known account literal must parse");
    account_id_runtime_literal(&account_id, Some(chain_discriminant))
}
#[cfg(test)]
fn localnet_client_account_literal(chain_discriminant: Option<u16>) -> String {
    account_id_runtime_literal(&localnet_client_account_id(), chain_discriminant)
}
#[allow(clippy::too_many_lines)]
/// Generate a localnet with an optional canonical chain identity and account-address prefix.
/// Fixed public chain prefixes reject conflicting explicit values before any output is created.
pub fn generate_localnet_with_chain<T: Write>(
    opts: &LocalnetOptions,
    writer: &mut BufWriter<T>,
    chain_id: Option<&str>,
    configured_discriminant: Option<u16>,
) -> Result<()> {
    generate_localnet_runtime(opts, writer, chain_id, configured_discriminant, false, None)
}

/// Materialize a native managed localnet without shell launchers or inherited seed descriptors.
pub fn generate_managed_localnet(opts: &LocalnetOptions) -> Result<()> {
    generate_managed_localnet_at(opts, None)
}

fn generate_managed_localnet_at(
    opts: &LocalnetOptions,
    publication_root: Option<&Path>,
) -> Result<()> {
    generate_localnet_runtime(
        opts,
        &mut BufWriter::new(std::io::sink()),
        None,
        None,
        true,
        publication_root,
    )
}

fn generate_localnet_runtime<T: Write>(
    opts: &LocalnetOptions,
    writer: &mut BufWriter<T>,
    chain_id: Option<&str>,
    configured_discriminant: Option<u16>,
    managed: bool,
    publication_root: Option<&Path>,
) -> Result<()> {
    init_instruction_registry();
    let chain_id = resolve_localnet_chain_id(chain_id)?;
    let chain_discriminant =
        resolve_localnet_chain_discriminant(&chain_id, configured_discriminant)?;
    let taira = chain_id == PUBLIC_TAIRA_CHAIN_ID;
    service_authorities::validate_selection(opts, managed, taira)?;
    let hosts = validate_localnet_options(opts)?;
    validate_port_ranges(opts.peers, opts.base_api_port, opts.base_p2p_port)?;
    if taira
        && (opts.peers.get() != TAIRA_TESTNET_PEERS
            || opts.consensus_mode != SumeragiConsensusMode::Npos
            || opts.sora_profile != Some(SoraProfile::Nexus))
    {
        return Err(eyre!(
            "the canonical Taira chain requires exactly four NPoS validators and the Nexus Sora profile"
        ));
    }
    if taira {
        require_taira_private_output_outside_git(&opts.out_dir)?;
    }
    crate::shell::quote_path(&opts.out_dir)
        .wrap_err("validate requested localnet output path for shell handoff commands")?;
    // No output path is created until every request-level invariant has been
    // checked. This keeps an invalid invocation retryable with the same path.
    let out_dir = crate::localnet::custody::prepare_empty_private_directory(&opts.out_dir)
        .wrap_err("prepare fresh localnet private output directory")?;
    let shell_out_dir = crate::shell::absolute_quote_path(&out_dir)
        .wrap_err("validate localnet output path for shell handoff commands")?;
    write_localnet_gitignore(&out_dir)?;
    let rans_tables_path = copy_rans_tables(&out_dir)?;
    let seed_bytes = opts.seed.as_ref().map(String::as_bytes);
    // Keep every account literal and permission payload emitted by this localnet
    // generation scoped to the selected chain.  Applying the guard only while
    // rendering/parsing peer configs is too late: the genesis and alias intent
    // have already serialized account IDs by then.
    let _chain_discriminant = chain_discriminant.map(ChainDiscriminantGuard::enter);
    let peers = build_peers(
        opts.peers.get(),
        seed_bytes,
        opts.base_api_port,
        opts.base_p2p_port,
    )
    .wrap_err("failed to generate localnet peer keys")?;
    let lane_manifest_directory = write_localnet_lane_manifests(
        &out_dir,
        opts.sora_profile,
        &peers,
        chain_discriminant,
        taira,
    )?;
    let client_identity = localnet_ephemeral_identity(seed_bytes, b"operator-root")?;
    let http_operator_identity = localnet_ephemeral_identity(seed_bytes, b"http-operator-root")?;
    let onboarding_identity = localnet_ephemeral_identity(seed_bytes, b"onboarding-root")?;
    let runtime_bundle = write_localnet_runtime_bundle(
        &out_dir,
        &client_identity,
        &http_operator_identity,
        &onboarding_identity,
    )?;
    let service_authorities = service_authorities::generate(
        opts.service_profile,
        &out_dir,
        seed_bytes,
        &client_identity,
        &http_operator_identity,
        &onboarding_identity,
    )?;
    if taira {
        write_taira_runtime_signer_keys(&out_dir, &peers)?;
    }
    if managed {
        prepare_managed_node_directories(&out_dir, peers.len())?;
    }
    let npos_bootstrap = localnet_uses_npos(opts.consensus_mode);
    let sora_profile_enabled = opts.sora_profile.is_some();
    let mcp_enabled = managed || sora_profile_enabled;
    let perf_spec = opts.perf_profile.map(LocalnetPerfProfile::spec);
    let queue_capacity = if perf_spec.is_some() {
        LOCALNET_PERF_QUEUE_CAPACITY
    } else {
        LOCALNET_QUEUE_CAPACITY
    };
    let logger_filter = perf_spec.map(|_| LOCALNET_PERF_LOGGER_FILTER);
    let signature_batch_max_ed25519 = perf_spec.map(|_| LOCALNET_SIGNATURE_BATCH_MAX_ED25519);
    // Sora profiles and NPoS bootstrap emit a dataspace catalog. Nexus itself is mandatory.
    let dataspace_fault_tolerance = (opts.sora_profile.is_some() || npos_bootstrap)
        .then(|| localnet_dataspace_fault_tolerance(opts.peers));
    let block_cadence_override = opts
        .block_cadence_ms
        .or_else(|| perf_spec.map(|spec| spec.block_cadence_ms));
    let block_cadence_ms = block_cadence_override.unwrap_or(LOCALNET_PIPELINE_TIME_MS);
    let tx_gossip_overrides = localnet_tx_gossip_overrides(block_cadence_ms);
    let block_max_transactions = perf_spec.map_or(LOCALNET_BLOCK_MAX_TRANSACTIONS, |spec| {
        spec.block_max_transactions
    });
    let requested_stake_amount = perf_spec.map(|spec| spec.stake_amount);
    let (genesis_public_key, genesis_private) = generate_genesis_key_pair(seed_bytes, GENESIS_SEED)
        .wrap_err("failed to generate localnet genesis key pair")?;
    let genesis_account_id = AccountId::new(genesis_public_key.clone());
    let assets = effective_localnet_assets_for_client(&opts.assets, &client_identity.account_id);
    let gas_account_id = localnet_gas_account_id(&genesis_public_key);
    let mut genesis = generate_raw_genesis(&genesis_public_key, opts.consensus_mode, &chain_id)?;
    genesis = append_localnet_private_root_admission_policy(genesis, &chain_id)?;
    if opts.extra_accounts > 0 || !assets.is_empty() {
        genesis = extend_genesis(
            genesis,
            &genesis_account_id,
            seed_bytes,
            opts.extra_accounts,
            &assets,
        )?;
    }
    genesis = append_localnet_service_accounts(
        genesis,
        &[
            Account::new(client_identity.account_id.clone()),
            Account::new(onboarding_identity.account_id.clone()),
        ],
    )?;
    genesis = append_localnet_service_fee_bootstrap(
        genesis,
        &genesis_account_id,
        &client_identity.account_id,
        &onboarding_identity.account_id,
    )?;
    if let Some(authorities) = service_authorities.as_ref() {
        genesis = authorities.append_genesis(
            genesis,
            &client_identity.account_id,
            &genesis_account_id,
        )?;
    }
    genesis = service_authorities::append_profile(
        genesis,
        opts.service_profile,
        &client_identity.account_id,
    )?;
    genesis = apply_parameter_overrides(
        genesis,
        opts.peers,
        Some(block_cadence_ms),
        block_max_transactions,
        opts.consensus_mode,
    )?;
    genesis = append_localnet_contract_permissions_for_client(
        genesis,
        &genesis_account_id,
        &client_identity.account_id,
    )?;
    genesis = append_peer_pop(genesis, &peers)?;
    let stake_amount =
        localnet_npos_stake_amount(&genesis.effective_parameters()?, requested_stake_amount)?;
    if npos_bootstrap {
        genesis = append_localnet_npos_bootstrap(
            genesis,
            &LocalnetNposBootstrapContext {
                peers: &peers,
                gas_account_id: &gas_account_id,
                stake_amount: &stake_amount,
                sora_profile: opts.sora_profile,
                genesis_account_id: &genesis_account_id,
                client_account_id: &client_identity.account_id,
                onboarding_account_id: &onboarding_identity.account_id,
                taira,
            },
        )?;
        genesis = append_private_dataspace_genesis_bootstrap_for_client(
            genesis,
            opts.sora_profile,
            &genesis_account_id,
            &client_identity.account_id,
        )?;
    } else {
        genesis =
            append_localnet_permissioned_support_accounts(genesis, &peers, &gas_account_id, taira)?;
    }
    genesis = apply_localnet_crypto_overrides(genesis)?;
    let alias_setup_request =
        localnet_alias_setup_request(&genesis_account_id, &client_identity.account_id, taira)?;
    let append_alias_setup_to_current_transaction = npos_bootstrap
        && matches!(
            opts.sora_profile,
            Some(SoraProfile::PrivateSbp | SoraProfile::PrivateCbuae | SoraProfile::PrivateBpng)
        );
    genesis = append_localnet_alias_setup(
        genesis,
        &alias_setup_request,
        append_alias_setup_to_current_transaction,
    )?;
    if service_authorities.is_some() {
        genesis = service_authorities::publication_client::append_namespace(
            genesis,
            &genesis_account_id,
            &client_identity.account_id,
        )?;
    }
    genesis =
        append_localnet_onboarding_permissions(genesis, &onboarding_identity.account_id, taira)?;
    let alias_setup_intent_path =
        write_localnet_alias_setup_intent(&out_dir, &alias_setup_request)?;
    let genesis_json_path = out_dir.join("genesis.json");
    let genesis_signed_path = out_dir.join("genesis.signed.nrt");
    let genesis_expected_hash_path = out_dir.join(GENESIS_EXPECTED_HASH_FILE);
    let gas_account_id = account_id_runtime_literal(&gas_account_id, chain_discriminant);
    let trusted = peers
        .iter()
        .map(|p| format!("{}@{}", p.public_key, hosts.public.addr_literal(p.p2p_port)))
        .collect::<Vec<_>>();
    let peer_telemetry_urls = peers
        .iter()
        .map(|p| hosts.public.torii_url(p.api_port))
        .collect::<Vec<_>>();
    let bls_entries = peers
        .iter()
        .map(|p| BlsEntry {
            bls_pk: p.bls_public_key.to_string(),
            pop_hex: format!("0x{}", hex::encode(&p.bls_pop)),
        })
        .collect::<Vec<_>>();
    let client_account_literal = client_identity.account_literal(chain_discriminant);
    // Runtime signer authorities must use the localnet chain's canonical
    // address prefix whenever the chain has a known discriminant.
    let operator_account_literal = client_identity.account_literal(chain_discriminant);
    let onboarding_account_literal = onboarding_identity.account_literal(chain_discriminant);
    let bootstrap_peer = peers
        .first()
        .expect("localnet always has at least one peer");
    let bootstrap_paths = LocalnetPeerStoragePaths::new(&out_dir, 0);
    let bootstrap_config = render_peer_config(
        bootstrap_peer,
        &trusted,
        &peer_telemetry_urls,
        &genesis_public_key,
        &genesis_signed_path,
        LocalnetGenesisIdentitySource::BootstrapInline(HashOf::from_untyped_unchecked(Hash::new(
            b"Kagami localnet policy-derivation placeholder",
        ))),
        &bls_entries,
        &bootstrap_paths,
        Some(rans_tables_path.as_path()),
        &chain_id,
        chain_discriminant,
        (&hosts.bind, &hosts.public),
        RenderPeerFeatures {
            mcp_enabled,
            npos_bootstrap,
            taira,
            operator_account: &operator_account_literal,
            operator_public_key: &http_operator_identity.public_key,
            onboarding_account: &onboarding_account_literal,
            runtime: Some(&runtime_bundle),
        },
        opts.sora_profile,
        lane_manifest_directory.as_deref(),
        dataspace_fault_tolerance,
        &gas_account_id,
        tx_gossip_overrides,
        logger_filter,
        signature_batch_max_ed25519,
        queue_capacity,
    );
    let bootstrap_config = match service_authorities.as_ref() {
        Some(authorities) => {
            authorities.configure_peer(&bootstrap_config, chain_discriminant, &out_dir, 0)?
        }
        None => bootstrap_config,
    };
    let config = parse_localnet_peer_config(&bootstrap_config, None)?;
    let genesis = append_localnet_native_lane_policy(genesis, &config.nexus)?;
    let da_proof_policies = Some(resolve_localnet_da_proof_policies(&config));
    // The genesis block runs under the protocol-default ZK validity policy;
    // a chain sets other values with `zk_validity_policy_v1` in its manifest.
    let confidential_policy_hash = iroha_core::state::default_genesis_confidential_policy_hash();
    let genesis = genesis
        .with_consensus_mode(opts.consensus_mode)
        .with_consensus_meta()?;
    let genesis_public_key_path = out_dir.join(GENESIS_PUBLIC_KEY_FILE);
    let genesis_private_key_path = out_dir.join(GENESIS_PRIVATE_KEY_FILE);
    write_genesis_key_files(
        &genesis_public_key_path,
        &genesis_private_key_path,
        &genesis_public_key,
        &genesis_private,
    )?;
    let genesis_expected_hash = write_genesis(GenesisWriteContext {
        manifest: &genesis,
        creation_time_ms: service_authorities
            .as_ref()
            .map(|authorities| authorities.creation_time_ms()),
        public_key: &genesis_public_key,
        private_key: genesis_private.clone(),
        config: &config,
        chain_discriminant,
        json_path: &genesis_json_path,
        signed_path: &genesis_signed_path,
        policies: GenesisConsensusPolicies {
            da_proof_policies,
            confidential_policy_hash,
        },
    })?;
    write_and_validate_genesis_expected_hash(
        &genesis_expected_hash_path,
        &genesis_signed_path,
        genesis_expected_hash,
    )?;
    if let Some(authorities) = service_authorities.as_ref() {
        authorities.publish(&out_dir, genesis_expected_hash, &client_identity.account_id)?;
    }
    let mut publication_client_selection = None;
    for (idx, peer) in peers.iter().enumerate() {
        let paths = LocalnetPeerStoragePaths::new(&out_dir, idx);
        custody::ensure_directory(&paths.kura)
            .wrap_err_with(|| format!("failed to create kura dir {}", paths.kura.display()))?;
        custody::ensure_directory(&paths.state).wrap_err_with(|| {
            format!("failed to create peer state dir {}", paths.state.display())
        })?;
        custody::ensure_directory(&paths.tiered_state).wrap_err_with(|| {
            format!(
                "failed to create tiered state dir {}",
                paths.tiered_state.display()
            )
        })?;
        custody::ensure_directory(&paths.da_store).wrap_err_with(|| {
            format!(
                "failed to create DA WSV snapshot dir {}",
                paths.da_store.display()
            )
        })?;
        let render = |render_root: &Path| -> Result<Zeroizing<String>> {
            let render_paths = LocalnetPeerStoragePaths::new(render_root, idx);
            let render_runtime = runtime_bundle.at_root(render_root);
            let render_manifests = lane_manifest_directory
                .as_ref()
                .map(|directory| {
                    directory
                        .strip_prefix(&out_dir)
                        .map(|relative| render_root.join(relative))
                })
                .transpose()?;
            let rendered = render_peer_config(
                peer,
                &trusted,
                &peer_telemetry_urls,
                &genesis_public_key,
                &render_root.join("genesis.signed.nrt"),
                LocalnetGenesisIdentitySource::PublishedFile,
                &bls_entries,
                &render_paths,
                Some(&render_root.join(LOCALNET_RANS_TABLE_RELATIVE_PATH)),
                &chain_id,
                chain_discriminant,
                (&hosts.bind, &hosts.public),
                RenderPeerFeatures {
                    mcp_enabled,
                    npos_bootstrap,
                    taira,
                    operator_account: &operator_account_literal,
                    operator_public_key: &http_operator_identity.public_key,
                    onboarding_account: &onboarding_account_literal,
                    runtime: Some(&render_runtime),
                },
                opts.sora_profile,
                render_manifests.as_deref(),
                dataspace_fault_tolerance,
                &gas_account_id,
                tx_gossip_overrides,
                logger_filter,
                signature_batch_max_ed25519,
                queue_capacity,
            );
            let rendered = match service_authorities.as_ref() {
                Some(authorities) => {
                    authorities.configure_peer(&rendered, chain_discriminant, render_root, idx)?
                }
                None => rendered,
            };
            if managed {
                managed_peer_config(&rendered, &managed_node_dir(render_root, idx))
            } else {
                Ok(rendered)
            }
        };
        let rendered = render(&out_dir)?;
        let path = out_dir.join(format!("peer{idx}.toml"));
        let parsed_config =
            parse_localnet_peer_config(&rendered, Some(&path)).wrap_err_with(|| {
                format!(
                    "generated validator config peer{idx}.toml failed Config/Catalog validation"
                )
            })?;
        if parsed_config.genesis.expected_hash != genesis_expected_hash {
            return Err(eyre!(
                "generated validator config peer{idx}.toml has genesis hash {}, expected {}",
                parsed_config.genesis.expected_hash,
                genesis_expected_hash
            ));
        }
        if idx == 0 {
            if let Some(authorities) = service_authorities.as_ref() {
                ensure!(
                    hosts.public.url_host() == "127.0.0.1",
                    "generated publication requires original numeric loopback Torii endpoints"
                );
                let signed =
                    iroha_fs::read_private(&genesis_signed_path, SIGNED_GENESIS_MAX_BYTES_V1)?;
                // Staging binds new consensus commitments into the published manifest. Project
                // the exact persisted bound bytes paired with this signed block.
                let bound_json = iroha_fs::read_private(
                    &genesis_json_path,
                    iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
                )?;
                validate_genesis_manifest_json(&bound_json)?;
                let bound_manifest = RawGenesisTransaction::from_json_slice_at_path(
                    &bound_json,
                    &genesis_json_path,
                )?;
                publication_client_selection = Some(authorities.publication_client_selection(
                    &bound_manifest,
                    &signed,
                    &parsed_config,
                    &out_dir,
                    &client_identity.account_id,
                    opts.base_api_port,
                )?);
            }
        }
        if idx < 3 && managed {
            if let Some(authorities) = service_authorities.as_ref() {
                authorities.initialize_native_attestation(
                    &out_dir,
                    &parsed_config.torii.sorafs_storage.data_dir,
                    genesis_expected_hash,
                    idx,
                )?;
                if idx == 0 {
                    authorities.initialize_publication(
                        &out_dir,
                        genesis_expected_hash,
                        &client_identity.account_id,
                    )?;
                }
            }
        }
        let rendered = match publication_root {
            Some(root) => render(root)?,
            None => rendered,
        };
        write_owner_only_localnet_file(&path, rendered.as_bytes())
            .wrap_err_with(|| format!("write validator config {}", path.display()))?;
    }
    if managed {
        write_client_config(
            &out_dir,
            opts.base_api_port,
            &hosts.public,
            &chain_id,
            chain_discriminant,
            &client_identity,
            publication_client_selection
                .as_ref()
                .map(|selection| &selection.table),
        )?;
        if let Some(selection) = publication_client_selection.as_ref() {
            selection.initialize_namespace_parent(&out_dir)?;
        }
        crate::localnet::custody::validate_private_tree(&out_dir, &[])
            .wrap_err("validate managed localnet private artifact tree")?;
        return Ok(());
    }
    let fee_asset_definition_id = localnet_xor_asset_literal();
    write_scripts(
        &out_dir,
        opts.peers.get(),
        sora_profile_enabled,
        taira,
        &client_account_literal,
        &fee_asset_definition_id,
    )?;
    write_client_config(
        &out_dir,
        opts.base_api_port,
        &hosts.public,
        &chain_id,
        chain_discriminant,
        &client_identity,
        publication_client_selection
            .as_ref()
            .map(|selection| &selection.table),
    )?;
    let primary_torii_url = hosts.public.torii_url(opts.base_api_port);
    let client_config_path = out_dir.join("client.toml");
    let start_path = out_dir.join("start.sh");
    let stop_path = out_dir.join("stop.sh");
    write_localnet_readme(
        &out_dir,
        &chain_id,
        opts.seed.as_deref(),
        opts.consensus_mode,
        opts.peers.get(),
        &primary_torii_url,
        &genesis_json_path,
        &genesis_signed_path,
        &genesis_expected_hash_path,
        &genesis_public_key_path,
        &genesis_private_key_path,
        &client_config_path,
        &start_path,
        &stop_path,
        &client_identity.account_literal(chain_discriminant),
        &onboarding_identity.account_id.to_string(),
        &runtime_bundle,
        &alias_setup_intent_path,
        &shell_out_dir,
    )?;
    crate::localnet::custody::validate_private_tree(
        &out_dir,
        &[start_path.as_path(), stop_path.as_path()],
    )
    .wrap_err("validate fresh localnet private artifact tree")?;
    writeln!(writer, "out_dir: {}", out_dir.display())?;
    writeln!(writer, "chain_id: {}", chain_id)?;
    writeln!(
        writer,
        "consensus_mode: {}",
        consensus_mode_label(opts.consensus_mode)
    )?;
    writeln!(writer, "peers: {}", opts.peers.get())?;
    writeln!(writer, "torii_url: {}", primary_torii_url)?;
    writeln!(writer, "genesis_json: {}", genesis_json_path.display())?;
    writeln!(writer, "genesis_signed: {}", genesis_signed_path.display())?;
    writeln!(
        writer,
        "genesis_expected_hash: {}",
        genesis_expected_hash_path.display()
    )?;
    writeln!(
        writer,
        "genesis_public_key: {}",
        genesis_public_key_path.display()
    )?;
    writeln!(
        writer,
        "genesis_private_key: {}",
        genesis_private_key_path.display()
    )?;
    writeln!(writer, "client_config: {}", client_config_path.display())?;
    writeln!(
        writer,
        "alias_setup_intent: {}",
        alias_setup_intent_path.display()
    )?;
    writeln!(
        writer,
        "operator_signer_key: {}",
        runtime_bundle.operator_signer_key.display()
    )?;
    writeln!(
        writer,
        "ledger_signer_key: {}",
        runtime_bundle.ledger_signer_key.display()
    )?;
    writeln!(
        writer,
        "onboarding_signer_key: {}",
        runtime_bundle.onboarding_signer_key.display()
    )?;
    writeln!(
        writer,
        "onboarding_token_file: {}",
        runtime_bundle.onboarding_token_file.display()
    )?;
    writeln!(writer, "start_script: {}", start_path.display())?;
    writeln!(writer, "stop_script: {}", stop_path.display())?;
    writeln!(writer, "guide: {}", out_dir.join("README.md").display())?;
    writeln!(
        writer,
        "next_start: cd {} && {}",
        shell_out_dir,
        localnet_script_command("start.sh")
    )?;
    writeln!(writer, "next_health: curl -sf {}health", primary_torii_url)?;
    writeln!(
        writer,
        "next_stop: cd {} && {}",
        shell_out_dir,
        localnet_script_command("stop.sh")
    )?;
    Ok(())
}
fn localnet_tx_gossip_overrides(block_cadence_ms: u64) -> Option<LocalnetTxGossipOverrides> {
    if block_cadence_ms > LOCALNET_PIPELINE_TIME_MS {
        return None;
    }
    Some(LocalnetTxGossipOverrides {
        period_ms: LOCALNET_TX_GOSSIP_PERIOD_FAST_MS,
        resend_ticks: LOCALNET_TX_GOSSIP_RESEND_TICKS_FAST,
    })
}
fn build_peers(count: u16, seed: Option<&[u8]>, base_api: u16, base_p2p: u16) -> Result<Vec<Peer>> {
    (0..count)
        .map(|nth| {
            let (bls_public, bls_secret, pop) = generate_bls_key_pair(seed, &nth.to_be_bytes())
                .wrap_err_with(|| format!("failed to generate BLS key pair for peer {nth}"))?;
            let (soranet_transport_public_key, soranet_transport_private_key) =
                generate_soranet_transport_key_pair(seed, &nth.to_be_bytes()).wrap_err_with(
                    || format!("failed to generate SoraNet transport key pair for peer {nth}"),
                )?;
            let (streaming_public_key, streaming_private_key) =
                generate_streaming_identity_key_pair(seed, &nth.to_be_bytes()).wrap_err_with(
                    || format!("failed to generate streaming identity key pair for peer {nth}"),
                )?;
            let (runtime_signer_public_key, runtime_signer_private_key) =
                generate_peer_ed25519_key_pair(
                    seed,
                    TAIRA_RUNTIME_SIGNER_SEED_DOMAIN,
                    &nth.to_be_bytes(),
                )
                .wrap_err_with(|| {
                    format!("failed to generate Taira runtime signer key pair for peer {nth}")
                })?;
            Ok(Peer {
                public_key: bls_public.clone(),
                private_key: bls_secret,
                soranet_transport_public_key,
                soranet_transport_private_key,
                streaming_public_key,
                streaming_private_key,
                bls_public_key: bls_public,
                bls_pop: pop,
                runtime_signer_public_key,
                runtime_signer_private_key,
                api_port: base_api + nth,
                p2p_port: base_p2p + nth,
            })
        })
        .collect()
}
fn validate_port_ranges(peers: NonZeroU16, base_api_port: u16, base_p2p_port: u16) -> Result<()> {
    if base_api_port == 0 {
        return Err(eyre!("base_api_port must be > 0"));
    }
    if base_p2p_port == 0 {
        return Err(eyre!("base_p2p_port must be > 0"));
    }
    let max_offset = u32::from(peers.get() - 1);
    let api_start = u32::from(base_api_port);
    let p2p_start = u32::from(base_p2p_port);
    let api_max = api_start + max_offset;
    if api_max > u32::from(u16::MAX) {
        return Err(eyre!(
            "base_api_port {} with {} peers exceeds u16 range",
            base_api_port,
            peers
        ));
    }
    let p2p_max = p2p_start + max_offset;
    if p2p_max > u32::from(u16::MAX) {
        return Err(eyre!(
            "base_p2p_port {} with {} peers exceeds u16 range",
            base_p2p_port,
            peers
        ));
    }
    let ranges_overlap = api_start <= p2p_max && p2p_start <= api_max;
    if ranges_overlap {
        return Err(eyre!(
            "base_api_port {} and base_p2p_port {} overlap for {} peers",
            base_api_port,
            base_p2p_port,
            peers
        ));
    }
    Ok(())
}
fn localnet_dataspace_catalog(
    sora_profile: Option<SoraProfile>,
    fault_tolerance: u32,
    taira: bool,
) -> Vec<toml::Value> {
    use toml::{Table, Value};
    let fault_tolerance = i64::from(fault_tolerance);
    let mut universal = Table::new();
    universal.insert("alias".into(), Value::String("universal".to_owned()));
    universal.insert("id".into(), Value::Integer(0));
    universal.insert(
        "description".into(),
        Value::String(
            "Shared public data space for core, governance, and zero-knowledge lanes".to_owned(),
        ),
    );
    universal.insert("fault_tolerance".into(), Value::Integer(fault_tolerance));
    let mut catalog = vec![Value::Table(universal)];
    if taira {
        assert_eq!(sora_profile, Some(SoraProfile::Nexus));
        // Each participant dataspace is identified only by its full SNS name hash. Its derived
        // identifier can exceed `i64::MAX`, so no TOML integer `id` is emitted.
        catalog.extend(TAIRA_PARTICIPANT_LANES.iter().map(|participant| {
            let mut entry = Table::new();
            entry.insert("alias".into(), Value::String(participant.alias.to_owned()));
            entry.insert(
                "manifest_hash".into(),
                Value::String(hex::encode(participant.manifest_hash())),
            );
            entry.insert(
                "description".into(),
                Value::String(participant.dataspace_description.to_owned()),
            );
            entry.insert("fault_tolerance".into(), Value::Integer(fault_tolerance));
            Value::Table(entry)
        }));
        return catalog;
    }
    let mut extra_dataspaces = match sora_profile {
        Some(SoraProfile::Nexus) => vec![
            (
                "paynet",
                i64::try_from(LOCALNET_PAYNET_ALIAS_DATASPACE_ID)
                    .expect("PAYNET dataspace id fits i64"),
                "PayNet private dataspace",
            ),
            (
                "nexus",
                i64::try_from(LOCALNET_CBUAE_ALIAS_DATASPACE_ID)
                    .expect("CBUAE dataspace id fits i64"),
                "Nexus service alias dataspace",
            ),
        ],
        Some(
            SoraProfile::Dataspace
            | SoraProfile::PrivateSbp
            | SoraProfile::PrivateCbuae
            | SoraProfile::PrivateBpng,
        )
        | None => Vec::new(),
    };
    if let Some(spec) = private_dataspace_spec(sora_profile) {
        extra_dataspaces.push((
            spec.alias,
            i64::try_from(spec.id).expect("private dataspace id fits i64"),
            spec.dataspace_description,
        ));
    }
    for (alias, id, description) in extra_dataspaces {
        let mut entry = Table::new();
        entry.insert("alias".into(), Value::String(alias.to_owned()));
        entry.insert("id".into(), Value::Integer(id));
        entry.insert(
            "manifest_hash".into(),
            Value::String(localnet_dataspace_manifest_hash(id)),
        );
        entry.insert("description".into(), Value::String(description.to_owned()));
        entry.insert("fault_tolerance".into(), Value::Integer(fault_tolerance));
        catalog.push(Value::Table(entry));
    }
    catalog
}
#[derive(Clone, norito::derive::JsonSerialize)]
struct LocalnetLaneManifestValidator {
    validator: String,
    peer_id: String,
}
#[derive(norito::derive::JsonSerialize)]
struct LocalnetLaneManifest {
    lane: String,
    governance: String,
    version: u32,
    validators: Vec<LocalnetLaneManifestValidator>,
    quorum: u32,
}
fn write_localnet_lane_manifests(
    out_dir: &Path,
    sora_profile: Option<SoraProfile>,
    peers: &[Peer],
    chain_discriminant: Option<u16>,
    taira: bool,
) -> Result<Option<PathBuf>> {
    // Every restricted lane is governed by exactly one Parliament manifest named by its alias.
    let aliases = if taira {
        assert_eq!(sora_profile, Some(SoraProfile::Nexus));
        TAIRA_PARTICIPANT_LANES
            .iter()
            .filter(|participant| participant.restricted())
            .map(|participant| participant.alias)
            .collect::<Vec<_>>()
    } else {
        let Some(spec) = private_dataspace_spec(sora_profile) else {
            return Ok(None);
        };
        vec![spec.alias]
    };
    let manifest_directory = out_dir.join("lane-manifests");
    custody::create_directory(&manifest_directory).wrap_err_with(|| {
        format!(
            "failed to create localnet lane manifest directory {}",
            manifest_directory.display()
        )
    })?;
    let validators = peers
        .iter()
        .map(|peer| {
            let account_id = peer.validator_account_id(taira);
            LocalnetLaneManifestValidator {
                validator: account_id_runtime_literal(&account_id, chain_discriminant),
                peer_id: PeerId::from(peer.public_key.clone()).to_string(),
            }
        })
        .collect::<Vec<_>>();
    let peer_count = u32::try_from(validators.len())
        .map_err(|_| eyre!("localnet lane manifest validator count exceeds u32"))?;
    let quorum = peer_count
        .checked_mul(2)
        .map(|value| value / 3)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| eyre!("localnet lane manifest quorum overflow"))?;
    if usize::try_from(quorum).map_or(true, |value| value > validators.len()) {
        return Err(eyre!(
            "localnet lane manifest quorum {quorum} exceeds {} validators",
            validators.len()
        ));
    }
    for alias in aliases {
        let manifest = LocalnetLaneManifest {
            lane: alias.to_owned(),
            governance: "parliament".to_owned(),
            version: 1,
            validators: validators.clone(),
            quorum,
        };
        let raw = norito::json::to_json_pretty(&manifest).wrap_err_with(|| {
            format!("serialize localnet {} lane manifest", alias.to_uppercase())
        })?;
        let manifest_path = manifest_directory.join(format!("{alias}.manifest.json"));
        custody::write(&manifest_path, raw).wrap_err_with(|| {
            format!(
                "failed to write localnet {} lane manifest {}",
                alias.to_uppercase(),
                manifest_path.display()
            )
        })?;
    }
    Ok(Some(manifest_directory))
}
fn localnet_dataspace_manifest_hash(id: i64) -> String {
    use std::fmt::Write as _;
    let id = u64::try_from(id).expect("dataspace id must be non-negative");
    let mut hex = String::with_capacity(64);
    for byte in id.to_le_bytes() {
        write!(&mut hex, "{byte:02x}").expect("writing to String should not fail");
    }
    hex.push_str("000000000000000000000000000000000000000000000000");
    hex
}
fn localnet_lane_catalog(
    sora_profile: Option<SoraProfile>,
    taira: bool,
) -> Option<(i64, Vec<toml::Value>)> {
    use toml::{Table, Value};
    if !localnet_uses_alias_multilane_catalog(sora_profile) {
        return None;
    }
    let private_profile = matches!(
        sora_profile,
        Some(SoraProfile::PrivateSbp | SoraProfile::PrivateCbuae | SoraProfile::PrivateBpng)
    );
    let mut lane_specs = if private_profile {
        vec![
            (
                0_i64,
                "core",
                "Primary public lane",
                "universal",
                "public",
                None,
            ),
            (
                1_i64,
                "governance",
                "Governance lane",
                "universal",
                "public",
                None,
            ),
            (
                2_i64,
                "zk",
                "Zero-knowledge lane",
                "universal",
                "public",
                None,
            ),
        ]
    } else {
        vec![
            (
                0_i64,
                "core",
                "Primary execution lane",
                "universal",
                "public",
                None,
            ),
            (
                1_i64,
                "governance",
                "Governance & parliament traffic",
                "universal",
                "public",
                None,
            ),
            (
                2_i64,
                "zk",
                "Zero-knowledge attachments",
                "universal",
                "public",
                None,
            ),
        ]
    };
    let lane_count = match sora_profile {
        Some(SoraProfile::Nexus) if taira => {
            lane_specs.extend(TAIRA_PARTICIPANT_LANES.iter().map(|participant| {
                let (visibility, governance) = match participant.admission {
                    TairaLaneAdmission::Public => ("public", None),
                    TairaLaneAdmission::Restricted => ("restricted", Some("parliament")),
                };
                (
                    i64::from(participant.lane_index),
                    participant.alias,
                    participant.lane_description,
                    participant.alias,
                    visibility,
                    governance,
                )
            }));
            TAIRA_LANE_COUNT
        }
        Some(SoraProfile::Nexus) => {
            lane_specs.extend([
                (
                    i64::from(LOCALNET_PAYNET_ALIAS_LANE_INDEX),
                    "paynet",
                    "PayNet private dataspace lane",
                    "paynet",
                    "public",
                    None,
                ),
                (
                    i64::from(LOCALNET_CBUAE_ALIAS_LANE_INDEX),
                    "nexus",
                    "Nexus service alias lane",
                    "nexus",
                    "public",
                    None,
                ),
            ]);
            LOCALNET_NEXUS_ALIAS_LANE_COUNT
        }
        Some(
            SoraProfile::Dataspace
            | SoraProfile::PrivateSbp
            | SoraProfile::PrivateCbuae
            | SoraProfile::PrivateBpng,
        ) => {
            let spec = private_dataspace_spec(sora_profile)
                .expect("private dataspace profile must have a typed specification");
            lane_specs.push((
                i64::from(spec.lane_index),
                spec.alias,
                spec.lane_description,
                spec.alias,
                "restricted",
                Some("parliament"),
            ));
            i64::from(spec.lane_index) + 1
        }
        None => return None,
    };
    let mut catalog = Vec::new();
    for (index, alias, description, dataspace, visibility, governance) in lane_specs {
        let mut entry = Table::new();
        entry.insert("index".into(), Value::Integer(index));
        entry.insert("alias".into(), Value::String(alias.to_owned()));
        entry.insert("description".into(), Value::String(description.to_owned()));
        entry.insert("dataspace".into(), Value::String(dataspace.to_owned()));
        entry.insert("visibility".into(), Value::String(visibility.to_owned()));
        if taira {
            entry.insert("storage".into(), Value::String("full_replica".to_owned()));
        }
        if let Some(governance) = governance {
            entry.insert("governance".into(), Value::String(governance.to_owned()));
        }
        entry.insert("metadata".into(), Value::Table(Table::new()));
        catalog.push(Value::Table(entry));
    }
    Some((lane_count, catalog))
}
#[allow(clippy::items_after_statements)]
fn localnet_routing_policy(sora_profile: Option<SoraProfile>, taira: bool) -> Option<toml::Table> {
    use toml::{Table, Value};
    if !localnet_uses_alias_multilane_catalog(sora_profile) {
        return None;
    }
    fn rule(
        lane: u32,
        dataspace: &str,
        matcher_key: &str,
        matcher_value: &str,
        description: Option<&str>,
    ) -> toml::Value {
        let mut matcher = Table::new();
        matcher.insert(
            matcher_key.to_owned(),
            Value::String(matcher_value.to_owned()),
        );
        let description = description.map_or_else(
            || match matcher_key {
                "instruction" => match matcher_value {
                    "governance" => {
                        "Route governance instructions to the governance lane".to_owned()
                    }
                    "smartcontract::deploy" => {
                        "Route contract deployments to the zk lane for proof tracking".to_owned()
                    }
                    _ => format!("Route {matcher_value} instructions to the {dataspace} lane"),
                },
                "account" => format!("Route {matcher_value} account traffic to {dataspace} lane"),
                _ => format!("Route {matcher_key}={matcher_value} traffic to {dataspace} lane"),
            },
            str::to_owned,
        );
        matcher.insert("description".into(), Value::String(description));
        let mut rule = Table::new();
        rule.insert("lane".into(), Value::Integer(i64::from(lane)));
        rule.insert("dataspace".into(), Value::String(dataspace.to_owned()));
        rule.insert("matcher".into(), Value::Table(matcher));
        Value::Table(rule)
    }
    let rules = match sora_profile {
        Some(SoraProfile::Nexus) if taira => {
            let mut rules = vec![
                rule(1, "universal", "instruction", "governance", None),
                rule(2, "universal", "instruction", "smartcontract::deploy", None),
            ];
            rules.extend(
                TAIRA_PARTICIPANT_LANES
                    .iter()
                    .filter(|participant| participant.account_route)
                    .map(|participant| {
                        rule(
                            participant.lane_index,
                            participant.alias,
                            "account",
                            &format!("*@{}", participant.alias),
                            None,
                        )
                    }),
            );
            rules
        }
        Some(SoraProfile::Nexus) => vec![
            rule(1, "universal", "instruction", "governance", None),
            rule(2, "universal", "instruction", "smartcontract::deploy", None),
            rule(
                LOCALNET_PAYNET_ALIAS_LANE_INDEX,
                "paynet",
                "account",
                "*@paynet",
                None,
            ),
            rule(
                LOCALNET_PAYNET_ALIAS_LANE_INDEX,
                "paynet",
                "account",
                "*@*.paynet",
                None,
            ),
        ],
        Some(SoraProfile::Dataspace) => {
            let spec = private_dataspace_spec(sora_profile)
                .expect("dataspace profile must have a typed specification");
            let mut rules = vec![
                rule(1, "universal", "instruction", "governance", None),
                rule(2, "universal", "instruction", "smartcontract::deploy", None),
            ];
            rules.extend(spec.account_routes.iter().map(|route| {
                rule(
                    spec.lane_index,
                    spec.alias,
                    "account",
                    route.matcher,
                    Some(route.description),
                )
            }));
            rules
        }
        Some(SoraProfile::PrivateSbp | SoraProfile::PrivateCbuae | SoraProfile::PrivateBpng) => {
            let spec = private_dataspace_spec(sora_profile)
                .expect("private dataspace profile must have a typed specification");
            let mut rules = spec
                .account_routes
                .iter()
                .map(|route| {
                    rule(
                        spec.lane_index,
                        spec.alias,
                        "account",
                        route.matcher,
                        Some(route.description),
                    )
                })
                .collect::<Vec<_>>();
            rules.extend([
                rule(
                    1,
                    "universal",
                    "instruction",
                    "governance",
                    Some(
                        "Route public governance instructions to the governance lane after private authority routes",
                    ),
                ),
                rule(
                    2,
                    "universal",
                    "instruction",
                    "smartcontract::deploy",
                    Some(
                        "Route public smart-contract deployment to the zk lane after private authority routes",
                    ),
                ),
            ]);
            rules.extend(spec.transfer_routes.iter().map(|route| {
                rule(
                    spec.lane_index,
                    spec.alias,
                    "instruction",
                    route.matcher,
                    Some(route.description),
                )
            }));
            rules
        }
        None => return None,
    };
    let mut policy = Table::new();
    policy.insert("default_lane".into(), Value::Integer(0));
    policy.insert(
        "default_dataspace".into(),
        Value::String("universal".to_owned()),
    );
    policy.insert("rules".into(), Value::Array(rules));
    Some(policy)
}
fn localnet_public_validator_lanes(sora_profile: Option<SoraProfile>, taira: bool) -> Vec<LaneId> {
    // Static lanes sharing one physical dataspace share the lowest stake-elected owner. The
    // universal governance and ZK lanes therefore inherit lane 0's validator pool, while a
    // restricted non-universal lane is governed by its authenticated lane manifest.
    let mut lanes = vec![LaneId::SINGLE];
    match sora_profile {
        Some(SoraProfile::Nexus) if taira => {
            lanes.extend(
                TAIRA_PARTICIPANT_LANES
                    .iter()
                    .filter(|participant| participant.admission == TairaLaneAdmission::Public)
                    .map(|participant| LaneId::new(participant.lane_index)),
            );
        }
        Some(SoraProfile::Nexus) => {
            lanes.push(LaneId::new(LOCALNET_PAYNET_ALIAS_LANE_INDEX));
            lanes.push(LaneId::new(LOCALNET_CBUAE_ALIAS_LANE_INDEX));
        }
        Some(
            SoraProfile::Dataspace
            | SoraProfile::PrivateSbp
            | SoraProfile::PrivateCbuae
            | SoraProfile::PrivateBpng,
        )
        | None => {}
    }
    lanes
}
/// Validate a disposable network chain label, refusing public mainnet impersonation.
pub fn resolve_localnet_chain_id(configured: Option<&str>) -> Result<String> {
    let chain_id = configured.unwrap_or(DEFAULT_CHAIN_ID);
    if chain_id.is_empty() {
        return Err(eyre!("`--chain-id` must not be empty"));
    }
    if chain_id.trim() != chain_id {
        return Err(eyre!(
            "`--chain-id` must not contain leading or trailing whitespace"
        ));
    }
    reject_retired_public_chain_id(chain_id)?;
    ensure!(
        chain_id != PUBLIC_NEXUS_CHAIN_ID,
        "disposable localnet cannot use the public Nexus chain identity; use genesis generate --profile iroha3-nexus --xor-asset-definition-id with the operator-selected mainnet XOR definition"
    );
    chain_id
        .parse::<ChainId>()
        .wrap_err("`--chain-id` must be canonical")?;
    Ok(chain_id.to_owned())
}
fn resolve_localnet_chain_discriminant(
    chain_id: &str,
    configured: Option<u16>,
) -> Result<Option<u16>> {
    let fixed = known_chain_discriminant_for_chain_id(chain_id);
    if let (Some(requested), Some(required)) = (configured, fixed) {
        ensure!(
            requested == required,
            "`--chain-discriminant` {requested} conflicts with the fixed prefix {required} for chain {chain_id}"
        );
    }
    Ok(configured.or(fixed))
}
#[derive(Clone, Copy)]
struct RenderPeerFeatures<'a> {
    mcp_enabled: bool,
    npos_bootstrap: bool,
    taira: bool,
    operator_account: &'a str,
    operator_public_key: &'a iroha_crypto::PublicKey,
    onboarding_account: &'a str,
    runtime: Option<&'a LocalnetRuntimeBundle>,
}
#[derive(Clone, Copy)]
enum LocalnetGenesisIdentitySource {
    BootstrapInline(HashOf<BlockHeader>),
    PublishedFile,
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn render_peer_config(
    peer: &Peer,
    trusted_peers: &[String],
    peer_telemetry_urls: &[String],
    genesis_public_key: &iroha_crypto::PublicKey,
    genesis_signed_path: &Path,
    genesis_identity: LocalnetGenesisIdentitySource,
    bls_entries: &[BlsEntry],
    storage_paths: &LocalnetPeerStoragePaths,
    rans_tables_path: Option<&Path>,
    chain_id: &str,
    chain_discriminant: Option<u16>,
    hosts: (&CanonicalHost, &CanonicalHost),
    features: RenderPeerFeatures<'_>,
    sora_profile: Option<SoraProfile>,
    lane_manifest_directory: Option<&Path>,
    dataspace_fault_tolerance: Option<u32>,
    gas_account_id: &str,
    tx_gossip_overrides: Option<LocalnetTxGossipOverrides>,
    logger_filter: Option<&str>,
    signature_batch_max_ed25519: Option<usize>,
    queue_capacity: usize,
) -> Zeroizing<String> {
    use iroha_config::parameters::defaults::streaming::codec as codec_defaults;
    use toml::{Table, Value};
    let (bind_host, public_host) = hosts;
    let RenderPeerFeatures {
        mcp_enabled,
        npos_bootstrap,
        taira,
        operator_account,
        operator_public_key,
        onboarding_account,
        runtime,
    } = features;
    let localnet_operator_account = operator_account.to_owned();
    let genesis_account = AccountId::new(genesis_public_key.clone());
    let genesis_account_literal = account_id_runtime_literal(&genesis_account, chain_discriminant);
    let fee_sponsor_program_id =
        format!("{genesis_account_literal}/{LOCALNET_FEE_SPONSOR_PROGRAM_NAME}");
    let trusted_list = trusted_peers
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let pops = bls_entries
        .iter()
        .map(|entry| {
            let mut t = Table::new();
            t.insert("public_key".into(), Value::String(entry.bls_pk.clone()));
            t.insert(
                "pop_hex".into(),
                Value::String(entry.pop_hex.trim_start_matches("0x").to_owned()),
            );
            Value::Table(t)
        })
        .collect::<Vec<_>>();
    let mut root = crate::secret_toml::Table::new(Table::new());
    root.insert("chain".into(), Value::String(chain_id.to_owned()));
    if let Some(chain_discriminant) = chain_discriminant {
        root.insert(
            "chain_discriminant".into(),
            Value::Integer(i64::from(chain_discriminant)),
        );
    }
    root.insert(
        "private_key".into(),
        Value::String(peer.private_key.to_string()),
    );
    root.insert(
        "public_key".into(),
        Value::String(peer.public_key.to_string()),
    );
    root.insert(
        "soranet_transport_private_key".into(),
        Value::String(peer.soranet_transport_private_key.to_string()),
    );
    root.insert(
        "soranet_transport_public_key".into(),
        Value::String(peer.soranet_transport_public_key.to_string()),
    );
    root.insert("trusted_peers".into(), Value::Array(trusted_list));
    root.insert("trusted_peers_pop".into(), Value::Array(pops));
    root.insert(
        "telemetry_profile".into(),
        Value::String(LOCALNET_TELEMETRY_PROFILE.to_owned()),
    );
    let mut kura = Table::new();
    kura.insert(
        "store_dir".into(),
        Value::String(storage_paths.kura.to_string_lossy().into_owned()),
    );
    kura.insert(
        "fsync_mode".into(),
        Value::String(LOCALNET_KURA_FSYNC_MODE.to_owned()),
    );
    root.insert("kura".into(), Value::Table(kura));
    let mut soracloud_runtime = Table::new();
    soracloud_runtime.insert(
        "state_dir".into(),
        Value::String(
            storage_paths
                .soracloud_runtime
                .to_string_lossy()
                .into_owned(),
        ),
    );
    if taira {
        soracloud_runtime.insert("production_mode".into(), Value::Boolean(true));
        soracloud_runtime.insert(
            "hydration_concurrency".into(),
            Value::Integer(TAIRA_SORACLOUD_HYDRATION_CONCURRENCY),
        );
        soracloud_runtime.insert(
            "prepared_runtime_cache_capacity".into(),
            Value::Integer(TAIRA_SORACLOUD_PREPARED_RUNTIME_CACHE_CAPACITY),
        );
        let (_, runtime_public_key) = peer
            .runtime_signer_public_key
            .try_to_bytes()
            .expect("generated Taira runtime signer public key must encode");
        let runtime_public_key_hex = hex::encode(runtime_public_key);
        let runtime_authority = account_id_runtime_literal(
            &AccountId::new(peer.runtime_signer_public_key.clone()),
            chain_discriminant,
        );
        let mut signer = Table::new();
        signer.insert(
            "handle".into(),
            Value::String(format!(
                "{TAIRA_RUNTIME_SIGNER_HANDLE_PREFIX}{runtime_public_key_hex}"
            )),
        );
        signer.insert("authority".into(), Value::String(runtime_authority));
        signer.insert("algorithm".into(), Value::String("ed25519".to_owned()));
        signer.insert(
            "public_key_hex".into(),
            Value::String(runtime_public_key_hex),
        );
        signer.insert(
            "revision".into(),
            Value::Integer(
                i64::try_from(TAIRA_RUNTIME_SIGNER_REVISION)
                    .expect("Taira runtime signer revision fits a TOML integer"),
            ),
        );
        signer.insert(
            "policy_digest_hex".into(),
            Value::String(hex::encode(taira_runtime_signer_policy_digest())),
        );
        let mut submission = Table::new();
        submission.insert("fee_payer".into(), Value::String("authority".to_owned()));
        submission.insert("signer".into(), Value::Table(signer));
        soracloud_runtime.insert("submission".into(), Value::Table(submission));

        let mut egress = Table::new();
        egress.insert("default_allow".into(), Value::Boolean(false));
        egress.insert("allowed_hosts".into(), Value::Array(Vec::new()));
        egress.insert(
            "rate_per_minute".into(),
            Value::Integer(i64::from(taira_defaults::INROU_EGRESS_RATE_PER_MINUTE)),
        );
        egress.insert(
            "max_bytes_per_minute".into(),
            Value::Integer(
                i64::try_from(taira_defaults::INROU_EGRESS_MAX_BYTES_PER_MINUTE)
                    .expect("Taira Inrou egress byte budget fits i64"),
            ),
        );
        soracloud_runtime.insert("egress".into(), Value::Table(egress));
    }
    root.insert("soracloud_runtime".into(), Value::Table(soracloud_runtime));
    let mut tiered_state = Table::new();
    tiered_state.insert(
        "cold_store_root".into(),
        Value::String(storage_paths.tiered_state.to_string_lossy().into_owned()),
    );
    tiered_state.insert(
        "da_store_root".into(),
        Value::String(storage_paths.da_store.to_string_lossy().into_owned()),
    );
    root.insert("tiered_state".into(), Value::Table(tiered_state));
    let mut sumeragi = Table::new();
    sumeragi.insert("role".into(), Value::String("validator".to_owned()));
    let mut keys = Table::new();
    keys.insert(
        "allowed_algorithms".into(),
        Value::Array(vec![Value::String("bls_normal".to_owned())]),
    );
    sumeragi.insert("keys".into(), Value::Table(keys));
    let mut nexus = Table::new();
    {
        let mut storage = Table::new();
        let storage_budget = if taira {
            taira_defaults::NEXUS_STORAGE_BUDGET_BYTES
        } else {
            LOCALNET_NEXUS_STORAGE_BUDGET_BYTES
        };
        storage.insert(
            "local_budget_bytes".into(),
            Value::Integer(
                i64::try_from(storage_budget).expect("localnet Nexus storage budget fits i64"),
            ),
        );
        if taira {
            storage.insert(
                "max_wsv_memory_bytes".into(),
                Value::Integer(
                    i64::try_from(taira_defaults::NEXUS_MAX_WSV_MEMORY_BYTES)
                        .expect("Taira WSV memory fits i64"),
                ),
            );
            let weights = TAIRA_NEXUS_STORAGE_WEIGHTS
                .into_iter()
                .map(|(name, value)| (name.to_owned(), Value::Integer(i64::from(value))))
                .collect();
            storage.insert("disk_budget_weights".into(), Value::Table(weights));
        }
        nexus.insert("storage".into(), Value::Table(storage));
    }
    let mut fusion = Table::new();
    fusion.insert(
        "exit_teu".into(),
        Value::Integer(i64::from(LOCALNET_LANE_TEU_CAPACITY)),
    );
    nexus.insert("fusion".into(), Value::Table(fusion));
    let stake_asset_id = localnet_xor_asset_literal();
    let mut staking = Table::new();
    staking.insert(
        "stake_asset_id".into(),
        Value::String(stake_asset_id.clone()),
    );
    staking.insert(
        "stake_escrow_account_id".into(),
        Value::String(gas_account_id.to_owned()),
    );
    staking.insert(
        "slash_sink_account_id".into(),
        Value::String(gas_account_id.to_owned()),
    );
    nexus.insert("staking".into(), Value::Table(staking));
    if npos_bootstrap || chain_discriminant.is_some() {
        let fee_asset_id = localnet_xor_asset_literal();
        let mut fees = Table::new();
        fees.insert("fee_asset_id".into(), Value::String(fee_asset_id));
        fees.insert("base_fee".into(), Value::String("0".to_owned()));
        fees.insert("per_byte_fee".into(), Value::String("0".to_owned()));
        fees.insert(
            "per_instruction_fee".into(),
            Value::String("0.001".to_owned()),
        );
        fees.insert(
            "per_gas_unit_fee".into(),
            Value::String("0.00005".to_owned()),
        );
        fees.insert("settlement_mode".into(), Value::String("direct".to_owned()));
        fees.insert(
            "fee_sink_account_id".into(),
            Value::String(gas_account_id.to_owned()),
        );
        fees.insert(
            "sponsor_vault_custody_account_id".into(),
            Value::String(gas_account_id.to_owned()),
        );
        nexus.insert("fees".into(), Value::Table(fees));
    }
    if let Some((lane_count, lane_catalog)) = localnet_lane_catalog(sora_profile, taira) {
        nexus.insert("lane_count".into(), Value::Integer(lane_count));
        nexus.insert("lane_catalog".into(), Value::Array(lane_catalog));
    }
    if let Some(fault_tolerance) = dataspace_fault_tolerance {
        let catalog = localnet_dataspace_catalog(sora_profile, fault_tolerance, taira);
        nexus.insert("dataspace_catalog".into(), Value::Array(catalog));
    }
    if let Some(policy) = localnet_routing_policy(sora_profile, taira) {
        nexus.insert("routing_policy".into(), Value::Table(policy));
    }
    if let Some(manifest_directory) = lane_manifest_directory {
        assert!(
            taira || private_dataspace_spec(sora_profile).is_some(),
            "lane manifests require a generated restricted dataspace"
        );
        let mut registry = Table::new();
        registry.insert(
            "manifest_directory".into(),
            Value::String(manifest_directory.to_string_lossy().into_owned()),
        );
        nexus.insert("registry".into(), Value::Table(registry));
        let mut parliament = Table::new();
        parliament.insert(
            "module_type".into(),
            Value::String("parliament_sortition_jit".to_owned()),
        );
        let mut parliament_params = Table::new();
        parliament_params.insert(
            "selection".into(),
            Value::String("multibody_sortition".to_owned()),
        );
        parliament_params.insert("approval_flow".into(), Value::String("jit".to_owned()));
        parliament.insert("params".into(), Value::Table(parliament_params));
        let mut modules = Table::new();
        modules.insert("parliament".into(), Value::Table(parliament));
        let mut governance = Table::new();
        if !taira {
            governance.insert(
                "default_module".into(),
                Value::String("parliament".to_owned()),
            );
        }
        governance.insert("modules".into(), Value::Table(modules));
        nexus.insert("governance".into(), Value::Table(governance));
    }
    root.insert("nexus".into(), Value::Table(nexus));
    // Safety records and the key installation log live beside the peer's state, outside Kura:
    // the start script asserts fresh keys exactly when the records directory does not exist.
    sumeragi.insert(
        "records_dir".into(),
        Value::String(
            storage_paths
                .state
                .join(LOCALNET_SUMERAGI_RECORDS_DIR)
                .to_string_lossy()
                .into_owned(),
        ),
    );
    sumeragi.insert(
        "installation_log".into(),
        Value::String(
            storage_paths
                .state
                .join(LOCALNET_SUMERAGI_INSTALLATION_LOG)
                .to_string_lossy()
                .into_owned(),
        ),
    );
    root.insert("sumeragi".into(), Value::Table(sumeragi));
    let mut pipeline = Table::new();
    if let Some(batch_max) = signature_batch_max_ed25519 {
        pipeline.insert(
            "signature_batch_max_ed25519".into(),
            Value::Integer(i64::try_from(batch_max).expect("batch size fits i64")),
        );
    }
    pipeline.insert("signature_batch_max_bls".into(), Value::Integer(4i64));
    let mut gas = Table::new();
    gas.insert(
        "tech_account_id".into(),
        Value::String(gas_account_id.to_owned()),
    );
    pipeline.insert("gas".into(), Value::Table(gas));
    root.insert("pipeline".into(), Value::Table(pipeline));
    let mut queue = Table::new();
    queue.insert(
        "capacity".into(),
        Value::Integer(i64::try_from(queue_capacity).expect("queue capacity fits i64")),
    );
    queue.insert(
        "capacity_per_user".into(),
        Value::Integer(i64::try_from(queue_capacity).expect("queue capacity fits i64")),
    );
    queue.insert(
        "transaction_time_to_live_ms".into(),
        Value::Integer(i64::try_from(LOCALNET_QUEUE_TTL_MS).expect("queue ttl fits i64")),
    );
    root.insert("queue".into(), Value::Table(queue));
    let mut crypto = Table::new();
    let allowed_signing = [
        iroha_crypto::Algorithm::Ed25519,
        iroha_crypto::Algorithm::Secp256k1,
        iroha_crypto::Algorithm::BlsNormal,
    ];
    crypto.insert(
        "allowed_signing".into(),
        Value::Array(
            allowed_signing
                .iter()
                .map(|algo| Value::String(algo.as_static_str().to_owned()))
                .collect(),
        ),
    );
    let mut curves = Table::new();
    let mut curve_ids = allowed_signing
        .iter()
        .filter_map(|algo| {
            iroha_data_model::account::curve::CurveId::try_from_algorithm(*algo).ok()
        })
        .map(|curve| i64::from(curve.as_u8()))
        .collect::<Vec<_>>();
    curve_ids.sort_unstable();
    curve_ids.dedup();
    curves.insert(
        "allowed_curve_ids".into(),
        Value::Array(curve_ids.into_iter().map(Value::Integer).collect()),
    );
    crypto.insert("curves".into(), Value::Table(curves));
    root.insert("crypto".into(), Value::Table(crypto));
    let mut streaming = Table::new();
    streaming.insert(
        "identity_public_key".into(),
        Value::String(peer.streaming_public_key.to_string()),
    );
    streaming.insert(
        "identity_private_key".into(),
        Value::String(peer.streaming_private_key.to_string()),
    );
    streaming.insert(
        "session_store_dir".into(),
        Value::String(
            storage_paths
                .streaming_sessions
                .to_string_lossy()
                .into_owned(),
        ),
    );
    if let Some(rans_tables_path) = rans_tables_path {
        let mut streaming_codec = Table::new();
        streaming_codec.insert(
            "cabac_mode".into(),
            Value::String(codec_defaults::CABAC_MODE.to_owned()),
        );
        streaming_codec.insert(
            "trellis_blocks".into(),
            Value::Array(
                codec_defaults::trellis_blocks()
                    .into_iter()
                    .map(|size| Value::Integer(i64::from(size)))
                    .collect(),
            ),
        );
        streaming_codec.insert(
            "rans_tables_path".into(),
            Value::String(rans_tables_path.to_string_lossy().into_owned()),
        );
        streaming_codec.insert(
            "entropy_mode".into(),
            Value::String(codec_defaults::entropy_mode()),
        );
        streaming_codec.insert(
            "bundle_width".into(),
            Value::Integer(i64::from(codec_defaults::bundle_width())),
        );
        streaming_codec.insert(
            "bundle_accel".into(),
            Value::String(codec_defaults::bundle_accel()),
        );
        streaming.insert("codec".into(), Value::Table(streaming_codec));
    }
    root.insert("streaming".into(), Value::Table(streaming));
    let mut sorafs_storage = Table::new();
    if sora_profile.is_some() {
        // Sora localnets install Nexus geometry but do not provision the governed compliance
        // controller or native signer providers needed for an embedded storage-provider role.
        // Record that non-provider posture explicitly in every generated peer configuration.
        sorafs_storage.insert("enabled".into(), Value::Boolean(false));
    }
    // Validator durability queues beneath the SoraFS root remain active even when provider
    // storage workers are disabled, so every generated peer must own a disjoint root.
    sorafs_storage.insert(
        "data_dir".into(),
        Value::String(storage_paths.sorafs.to_string_lossy().into_owned()),
    );
    if taira {
        sorafs_storage.insert(
            "max_capacity_bytes".into(),
            Value::Integer(
                i64::try_from(taira_defaults::SORAFS_STORAGE_CAP_BYTES)
                    .expect("Taira SoraFS storage cap fits i64"),
            ),
        );
    }
    let mut sorafs = Table::new();
    sorafs.insert("storage".into(), Value::Table(sorafs_storage));
    let mut sorafs_por = Table::new();
    sorafs_por.insert(
        "state_dir".into(),
        Value::String(storage_paths.sorafs_por.to_string_lossy().into_owned()),
    );
    sorafs.insert("por".into(), Value::Table(sorafs_por));
    root.insert("sorafs".into(), Value::Table(sorafs));
    if let Some(chain_discriminant) = chain_discriminant {
        let mut governance = Table::new();
        let citizenship_escrow_account = account_id_runtime_literal(
            &iroha_config::parameters::defaults::governance::citizenship_escrow_account_id(),
            Some(chain_discriminant),
        );
        let bond_escrow_account = account_id_runtime_literal(
            &iroha_config::parameters::defaults::governance::bond_escrow_account_id(),
            Some(chain_discriminant),
        );
        let slash_receiver_account = account_id_runtime_literal(
            &iroha_config::parameters::defaults::governance::slash_receiver_account_id(),
            Some(chain_discriminant),
        );
        let sorafs_pin_fee_treasury_account = account_id_runtime_literal(
            &iroha_config::parameters::defaults::governance::sorafs_pin_fee::treasury_account_id(),
            Some(chain_discriminant),
        );
        governance.insert(
            "citizenship_escrow_account".into(),
            Value::String(citizenship_escrow_account),
        );
        governance.insert(
            "bond_escrow_account".into(),
            Value::String(bond_escrow_account),
        );
        governance.insert(
            "slash_receiver_account".into(),
            Value::String(slash_receiver_account.clone()),
        );
        governance.insert(
            "viral_incentive_pool_account".into(),
            Value::String(slash_receiver_account.clone()),
        );
        governance.insert(
            "viral_escrow_account".into(),
            Value::String(slash_receiver_account),
        );
        governance.insert(
            "sorafs_pin_fee_treasury_account".into(),
            Value::String(sorafs_pin_fee_treasury_account),
        );
        let telemetry_submitters =
            iroha_config::parameters::defaults::governance::sorafs_telemetry::submitters()
                .into_iter()
                .map(|literal| {
                    Value::String(account_literal_for_chain_discriminant(
                        &literal,
                        chain_discriminant,
                    ))
                })
                .collect();
        let mut sorafs_telemetry = Table::new();
        sorafs_telemetry.insert("submitters".into(), Value::Array(telemetry_submitters));
        governance.insert("sorafs_telemetry".into(), Value::Table(sorafs_telemetry));
        root.insert("gov".into(), Value::Table(governance));
    }
    let mut confidential = Table::new();
    confidential.insert("enabled".into(), Value::Boolean(true));
    confidential.insert("assume_valid".into(), Value::Boolean(false));
    root.insert("confidential".into(), Value::Table(confidential));
    let mut genesis = Table::new();
    genesis.insert(
        "file".into(),
        Value::String(genesis_signed_path.to_string_lossy().into_owned()),
    );
    genesis.insert(
        "public_key".into(),
        Value::String(genesis_public_key.to_string()),
    );
    match genesis_identity {
        LocalnetGenesisIdentitySource::BootstrapInline(expected_hash) => {
            genesis.insert(
                "expected_hash".into(),
                Value::String(NetworkId::from_genesis_hash(expected_hash).to_string()),
            );
        }
        LocalnetGenesisIdentitySource::PublishedFile => {
            genesis.insert(
                "expected_hash_file".into(),
                Value::String(GENESIS_EXPECTED_HASH_FILE.to_owned()),
            );
        }
    }
    root.insert("genesis".into(), Value::Table(genesis));
    let mut logger = Table::new();
    logger.insert("format".into(), Value::String("compact".into()));
    logger.insert("level".into(), Value::String("info".into()));
    if let Some(filter) = logger_filter {
        logger.insert("filter".into(), Value::String(filter.to_owned()));
    }
    root.insert("logger".into(), Value::Table(logger));
    let mut network = Table::new();
    network.insert(
        "address".into(),
        Value::String(bind_host.addr_literal(peer.p2p_port)),
    );
    network.insert(
        "public_address".into(),
        Value::String(public_host.addr_literal(peer.p2p_port)),
    );
    network.insert(
        "max_total_connections".into(),
        Value::Integer(
            i64::try_from(LOCALNET_MAX_TOTAL_CONNECTIONS)
                .expect("LOCALNET_MAX_TOTAL_CONNECTIONS fits i64"),
        ),
    );
    network.insert(
        "p2p_subscriber_queue_cap".into(),
        Value::Integer(
            i64::try_from(LOCALNET_P2P_SUBSCRIBER_QUEUE_CAP)
                .expect("LOCALNET_P2P_SUBSCRIBER_QUEUE_CAP fits i64"),
        ),
    );
    network.insert(
        "max_frame_bytes".into(),
        Value::Integer(i64::try_from(LOCALNET_MAX_FRAME_BYTES).expect("frame cap fits i64")),
    );
    network.insert(
        "max_frame_bytes_consensus".into(),
        Value::Integer(
            i64::try_from(LOCALNET_MAX_FRAME_BYTES_CONSENSUS)
                .expect("consensus frame cap fits i64"),
        ),
    );
    network.insert(
        "max_frame_bytes_control".into(),
        Value::Integer(
            i64::try_from(LOCALNET_MAX_FRAME_BYTES_CONTROL).expect("control frame cap fits i64"),
        ),
    );
    network.insert(
        "max_frame_bytes_block_sync".into(),
        Value::Integer(
            i64::try_from(LOCALNET_MAX_FRAME_BYTES_BLOCK_SYNC)
                .expect("block sync frame cap fits i64"),
        ),
    );
    network.insert(
        "max_frame_bytes_tx_gossip".into(),
        Value::Integer(
            i64::try_from(LOCALNET_MAX_FRAME_BYTES_TX_GOSSIP_NEXUS)
                .expect("tx gossip frame cap fits i64"),
        ),
    );
    network.insert(
        "max_frame_bytes_peer_gossip".into(),
        Value::Integer(
            i64::try_from(LOCALNET_MAX_FRAME_BYTES_PEER_GOSSIP)
                .expect("peer gossip frame cap fits i64"),
        ),
    );
    network.insert(
        "max_frame_bytes_health".into(),
        Value::Integer(
            i64::try_from(LOCALNET_MAX_FRAME_BYTES_HEALTH).expect("health frame cap fits i64"),
        ),
    );
    network.insert(
        "max_frame_bytes_other".into(),
        Value::Integer(
            i64::try_from(LOCALNET_MAX_FRAME_BYTES_OTHER).expect("other frame cap fits i64"),
        ),
    );
    network.insert(
        "consensus_ingress_rate_per_sec".into(),
        Value::Integer(i64::from(LOCALNET_CONSENSUS_INGRESS_RATE_PER_SEC)),
    );
    network.insert(
        "consensus_ingress_burst".into(),
        Value::Integer(i64::from(LOCALNET_CONSENSUS_INGRESS_BURST)),
    );
    network.insert(
        "consensus_ingress_bytes_per_sec".into(),
        Value::Integer(i64::from(LOCALNET_CONSENSUS_INGRESS_BYTES_PER_SEC)),
    );
    network.insert(
        "consensus_ingress_bytes_burst".into(),
        Value::Integer(i64::from(LOCALNET_CONSENSUS_INGRESS_BYTES_BURST)),
    );
    network.insert(
        "consensus_ingress_critical_rate_per_sec".into(),
        Value::Integer(i64::from(LOCALNET_CONSENSUS_INGRESS_CRITICAL_RATE_PER_SEC)),
    );
    network.insert(
        "consensus_ingress_critical_burst".into(),
        Value::Integer(i64::from(LOCALNET_CONSENSUS_INGRESS_CRITICAL_BURST)),
    );
    network.insert(
        "consensus_ingress_critical_bytes_per_sec".into(),
        Value::Integer(i64::from(LOCALNET_CONSENSUS_INGRESS_CRITICAL_BYTES_PER_SEC)),
    );
    network.insert(
        "consensus_ingress_critical_bytes_burst".into(),
        Value::Integer(i64::from(LOCALNET_CONSENSUS_INGRESS_CRITICAL_BYTES_BURST)),
    );
    let mut soranet_pow = Table::new();
    soranet_pow.insert(
        "revocation_store_path".into(),
        Value::String(
            storage_paths
                .soranet_ticket_revocations
                .to_string_lossy()
                .into_owned(),
        ),
    );
    let mut soranet_handshake = Table::new();
    soranet_handshake.insert("pow".into(), Value::Table(soranet_pow));
    network.insert("soranet_handshake".into(), Value::Table(soranet_handshake));
    // The disabled VPN profile still parses its operator account. Pin it to the
    // generated localnet authority so strict V1 address parsing uses this chain's prefix.
    let mut soranet_vpn = Table::new();
    soranet_vpn.insert(
        "operator_account_id".into(),
        Value::String(localnet_operator_account.clone()),
    );
    network.insert("soranet_vpn".into(), Value::Table(soranet_vpn));
    if let Some(overrides) = tx_gossip_overrides {
        network.insert(
            "transaction_gossip_period_ms".into(),
            Value::Integer(
                i64::try_from(overrides.period_ms)
                    .expect("LOCALNET_TX_GOSSIP_PERIOD_FAST_MS fits i64"),
            ),
        );
        network.insert(
            "transaction_gossip_resend_ticks".into(),
            Value::Integer(i64::from(overrides.resend_ticks)),
        );
        network.insert(
            "transaction_gossip_public_target_reshuffle_ms".into(),
            Value::Integer(
                i64::try_from(overrides.period_ms)
                    .expect("LOCALNET_TX_GOSSIP_PERIOD_FAST_MS fits i64"),
            ),
        );
        network.insert(
            "transaction_gossip_restricted_target_reshuffle_ms".into(),
            Value::Integer(
                i64::try_from(overrides.period_ms)
                    .expect("LOCALNET_TX_GOSSIP_PERIOD_FAST_MS fits i64"),
            ),
        );
    }
    root.insert("network".into(), Value::Table(network));
    let mut torii = Table::new();
    // The runtime operator sidecar is generated from this same identity. Bind
    // its public key on every peer while retaining node-key and replay guards.
    let mut operator_signatures = Table::new();
    operator_signatures.insert("enabled".into(), Value::Boolean(true));
    operator_signatures.insert(
        "allowed_public_keys".into(),
        Value::Array(vec![Value::String(operator_public_key.to_string())]),
    );
    torii.insert(
        "operator_signatures".into(),
        Value::Table(operator_signatures),
    );
    torii.insert(
        "address".into(),
        Value::String(bind_host.addr_literal(peer.api_port)),
    );
    torii.insert(
        "data_dir".into(),
        Value::String(storage_paths.torii.to_string_lossy().into_owned()),
    );
    let mut da_ingest = Table::new();
    da_ingest.insert(
        "replay_cache_store_dir".into(),
        Value::String(
            storage_paths
                .torii_da_replay_cache
                .to_string_lossy()
                .into_owned(),
        ),
    );
    da_ingest.insert(
        "manifest_store_dir".into(),
        Value::String(
            storage_paths
                .torii_da_manifests
                .to_string_lossy()
                .into_owned(),
        ),
    );
    torii.insert("da_ingest".into(), Value::Table(da_ingest));
    torii.insert(
        "peer_telemetry_urls".into(),
        Value::Array(
            peer_telemetry_urls
                .iter()
                .cloned()
                .map(Value::String)
                .collect::<Vec<_>>(),
        ),
    );
    torii.insert(
        "preauth_allow_cidrs".into(),
        Value::Array(
            LOCALNET_PREAUTH_ALLOW_CIDRS
                .iter()
                .map(|cidr| Value::String((*cidr).to_string()))
                .collect::<Vec<_>>(),
        ),
    );
    torii.insert(
        "preauth_rate_per_ip_per_sec".into(),
        Value::Integer(i64::from(LOCALNET_TORII_PREAUTH_RATE_PER_IP_PER_SEC)),
    );
    torii.insert(
        "preauth_burst_per_ip".into(),
        Value::Integer(i64::from(LOCALNET_TORII_PREAUTH_BURST_PER_IP)),
    );
    torii.insert(
        "api_rate_limit_bypass_cidrs".into(),
        Value::Array(
            LOCALNET_PREAUTH_ALLOW_CIDRS
                .iter()
                .map(|cidr| Value::String((*cidr).to_string()))
                .collect::<Vec<_>>(),
        ),
    );
    torii.insert(
        "internal_api_trusted_cidrs".into(),
        Value::Array(
            LOCALNET_INTERNAL_API_TRUSTED_CIDRS
                .iter()
                .map(|cidr| Value::String((*cidr).to_string()))
                .collect::<Vec<_>>(),
        ),
    );
    torii.insert(
        "tx_rate_per_authority_per_sec".into(),
        Value::Integer(i64::from(LOCALNET_TORII_TX_RATE_PER_AUTHORITY_PER_SEC)),
    );
    torii.insert(
        "tx_burst_per_authority".into(),
        Value::Integer(i64::from(LOCALNET_TORII_TX_BURST_PER_AUTHORITY)),
    );
    torii.insert(
        "api_high_load_tx_threshold".into(),
        Value::Integer(i64::try_from(queue_capacity).expect("queue capacity fits i64")),
    );
    torii.insert(
        "max_content_len".into(),
        Value::Integer(
            i64::try_from(LOCALNET_TORII_MAX_CONTENT_LEN)
                .expect("LOCALNET_TORII_MAX_CONTENT_LEN fits i64"),
        ),
    );
    // Generated localnet and prepared-Compose bundles do not yet project an
    // immutable prover-key directory into every validator container.
    // TODO: enable this profile once the key directory is captured and mounted.
    torii.insert("zk_prover_enabled".into(), Value::Boolean(false));
    if mcp_enabled {
        let mut mcp = Table::new();
        mcp.insert("enabled".into(), Value::Boolean(true));
        mcp.insert("profile".into(), Value::String("writer".into()));
        mcp.insert("expose_operator_routes".into(), Value::Boolean(false));
        mcp.insert(
            "allow_tool_prefixes".into(),
            Value::Array(vec![Value::String("iroha.".into())]),
        );
        torii.insert("mcp".into(), Value::Table(mcp));
    }
    if let Some(runtime) = runtime {
        let mut account_onboarding = Table::new();
        account_onboarding.insert(
            "authority".into(),
            Value::String(onboarding_account.to_owned()),
        );
        account_onboarding.insert(
            "private_key_file".into(),
            Value::String(runtime.onboarding_signer_key.to_string_lossy().into_owned()),
        );
        account_onboarding.insert("lease_term_years".into(), Value::Integer(1));
        account_onboarding.insert("additional_permissions".into(), Value::Array(Vec::new()));
        let mut credential_scope = Table::new();
        if taira {
            credential_scope.insert(
                "dataspace".into(),
                Value::String(TAIRA_CANARY_DATASPACE_ALIAS.to_owned()),
            );
        } else {
            credential_scope.insert(
                "domain".into(),
                Value::String(CLIENT_ACCOUNT_DOMAIN.to_owned()),
            );
        }
        let mut credential = Table::new();
        credential.insert(
            "id".into(),
            Value::String(LOCALNET_ONBOARDING_CREDENTIAL_ID.to_owned()),
        );
        credential.insert("scope".into(), Value::Table(credential_scope));
        credential.insert(
            "token_hash".into(),
            Value::String(format!(
                "blake3:{}",
                hex::encode(runtime.onboarding_token_hash)
            )),
        );
        account_onboarding.insert(
            "credentials".into(),
            Value::Array(vec![Value::Table(credential)]),
        );
        if npos_bootstrap {
            account_onboarding.insert(
                "fee_sponsor_program_id".into(),
                Value::String(fee_sponsor_program_id),
            );
        }
        torii.insert(
            "account_onboarding".into(),
            Value::Table(account_onboarding),
        );
        let mut faucet = Table::new();
        faucet.insert("enabled".into(), Value::Boolean(true));
        faucet.insert(
            "authority".into(),
            Value::String(localnet_operator_account.clone()),
        );
        faucet.insert(
            "private_key_file".into(),
            Value::String(runtime.ledger_signer_key.to_string_lossy().into_owned()),
        );
        faucet.insert(
            "asset_definition_id".into(),
            Value::String(localnet_xor_asset_literal()),
        );
        faucet.insert(
            "amount".into(),
            Value::String(LOCALNET_FAUCET_AMOUNT.to_owned()),
        );
        faucet.insert(
            "pow_difficulty_bits".into(),
            Value::Integer(LOCALNET_FAUCET_POW_DIFFICULTY_BITS),
        );
        faucet.insert(
            "pow_scrypt_log_n".into(),
            Value::Integer(LOCALNET_FAUCET_POW_SCRYPT_LOG_N),
        );
        faucet.insert(
            "pow_scrypt_r".into(),
            Value::Integer(LOCALNET_FAUCET_POW_SCRYPT_R),
        );
        faucet.insert(
            "pow_scrypt_p".into(),
            Value::Integer(LOCALNET_FAUCET_POW_SCRYPT_P),
        );
        faucet.insert(
            "pow_max_anchor_age_blocks".into(),
            Value::Integer(LOCALNET_FAUCET_POW_MAX_ANCHOR_AGE_BLOCKS),
        );
        faucet.insert(
            "pow_adaptive_lookback_blocks".into(),
            Value::Integer(LOCALNET_FAUCET_POW_ADAPTIVE_LOOKBACK_BLOCKS),
        );
        faucet.insert(
            "pow_adaptive_claims_per_extra_bit".into(),
            Value::Integer(LOCALNET_FAUCET_POW_ADAPTIVE_CLAIMS_PER_EXTRA_BIT),
        );
        faucet.insert(
            "pow_adaptive_max_extra_bits".into(),
            Value::Integer(LOCALNET_FAUCET_POW_ADAPTIVE_MAX_EXTRA_BITS),
        );
        // Local generated networks do not have finalized public Taira VRF seed material.
        faucet.insert("pow_beacon_seed_enabled".into(), Value::Boolean(false));
        torii.insert("faucet".into(), Value::Table(faucet));
    }
    // torii.transport.norito_rpc
    let mut norito_rpc = Table::new();
    norito_rpc.insert("enabled".into(), Value::Boolean(true));
    norito_rpc.insert("require_mtls".into(), Value::Boolean(false));
    norito_rpc.insert("stage".into(), Value::String("ga".into()));
    norito_rpc.insert(
        "allowed_clients".into(),
        Value::Array(vec![Value::String("*".into())]),
    );
    let mut transport = Table::new();
    transport.insert("norito_rpc".into(), Value::Table(norito_rpc));
    torii.insert("transport".into(), Value::Table(transport));
    root.insert("torii".into(), Value::Table(torii));
    Zeroizing::new(toml::to_string(&*root).expect("serializing peer config to TOML"))
}
fn generate_raw_genesis(
    genesis_public_key: &iroha_crypto::PublicKey,
    consensus_mode: SumeragiConsensusMode,
    chain_id: &str,
) -> Result<RawGenesisTransaction> {
    let chain_id = chain_id
        .parse::<ChainId>()
        .wrap_err("localnet chain id must be canonical")?;
    let npos_epoch_seed = matches!(consensus_mode, SumeragiConsensusMode::Npos)
        .then(|| localnet_npos_epoch_seed(&chain_id));
    let builder = GenesisBuilder::new_without_executor(chain_id, PathBuf::from("."))
        .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended());
    generate_default(
        builder,
        genesis_public_key,
        None,
        consensus_mode,
        None,
        npos_epoch_seed,
    )
}

fn extend_genesis(
    genesis: RawGenesisTransaction,
    genesis_account_id: &AccountId,
    seed_bytes: Option<&[u8]>,
    extra_accounts: u16,
    assets: &[AssetSpec],
) -> Result<RawGenesisTransaction> {
    let mut registrations = BootstrapRegistrations::from_manifest(&genesis);
    let extended_batch =
        genesis.transactions().len().checked_sub(1).ok_or_else(|| {
            eyre!("localnet asset extension requires a bootstrap permission phase")
        })?;
    let bootstrap = &genesis.transactions()[extended_batch];
    ensure!(
        !bootstrap.instructions().is_empty()
            && bootstrap.instructions().iter().all(|instruction| {
                matches!(
                    instruction.as_any().downcast_ref::<GrantBox>(),
                    Some(GrantBox::Permission(grant))
                        if grant.destination() == genesis_account_id
                )
            }),
        "localnet asset extension requires the generated authority's bootstrap permission phase"
    );
    // generate_default leaves its global permission phase open. Continue it with
    // global account/asset custody, separating scoped domain registration below.
    // The lower owner refuses structured parameters, topology, and IVM triggers.
    let mut current_length = bootstrap.instructions().len();
    let mut builder = genesis.into_builder();
    let mut lengths = Vec::new();
    for idx in 0..extra_accounts {
        let (pk, _) = generate_account_key_pair(seed_bytes, &format!("acct{idx}").into_bytes())
            .wrap_err_with(|| format!("failed to generate localnet extra account key {idx}"))?;
        let account_id = AccountId::new(pk.clone());
        if registrations.accounts.insert(account_id.clone()) {
            builder = builder.append_instruction(Register::account(Account::new(account_id)));
            current_length += 1;
        }
    }
    for asset in assets {
        if registrations.accounts.insert(asset.owned_by.clone()) {
            builder =
                builder.append_instruction(Register::account(Account::new(asset.owned_by.clone())));
            current_length += 1;
        }
        if registrations.accounts.insert(asset.mint_to.clone()) {
            builder =
                builder.append_instruction(Register::account(Account::new(asset.mint_to.clone())));
            current_length += 1;
        }
        let asset_def = AssetDefinitionId::parse_address_literal(&asset.id)
            .wrap_err("invalid asset definition id")?;
        let definition = AssetDefinition::new(
            asset_def.clone(),
            asset.name.clone(),
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .with_metadata(Metadata::default());
        builder = builder.append_instruction(Register::asset_definition(definition));
        current_length += 1;
        if let Some(alias_literal) = asset.alias.as_deref() {
            let alias = alias_literal
                .parse::<AssetDefinitionAlias>()
                .wrap_err("invalid asset definition alias")?;
            let scoped = alias.dataspace_segment() != "universal";
            // Alias binding resolves its namespace during genesis execution.
            // Materialize only the explicitly requested namespace before binding.
            if let Some(domain_name) = alias.domain_segment() {
                let domain = DomainId::try_new(domain_name, alias.dataspace_segment())?;
                if registrations.domains.insert(domain.clone()) {
                    if scoped && current_length > 0 {
                        lengths.push(current_length);
                        current_length = 0;
                    }
                    builder = builder.append_instruction(Register::domain(Domain::new(domain)));
                    current_length += 1;
                    if scoped {
                        lengths.push(current_length);
                        current_length = 0;
                    }
                }
            }
            builder = builder.append_instruction(SetAssetDefinitionAlias::bind(
                asset_def.clone(),
                alias,
                None,
            ));
            current_length += 1;
            // Routing authenticates this input against its original World: the
            // newly registered global definition has no alias there. Binding,
            // global balance minting and ownership transfer form this atomic
            // global phase after the scoped domain has been committed.
        }
        if asset.quantity > 0 {
            builder = builder.append_instruction(Mint::asset_quantity(
                asset.quantity,
                AssetId::new(asset_def.clone(), asset.mint_to.clone()),
            ));
            current_length += 1;
        }
        if asset.owned_by != *genesis_account_id {
            builder = builder.append_instruction(Transfer::asset_definition(
                genesis_account_id.clone(),
                asset_def,
                asset.owned_by.clone(),
            ));
            current_length += 1;
        }
    }
    if current_length > 0 {
        lengths.push(current_length);
    }
    let manifest = builder.build_raw()?;
    if lengths.is_empty() {
        return Ok(manifest);
    }
    // This global bootstrap phase can mix asset custody with scoped domain
    // registration. Separate only these instructions before staging, preserving every
    // other bootstrap phase, including atomic temporary-role alias setup.
    manifest.partition_instruction_only_transaction(extended_batch, &lengths)
}
fn localnet_npos_epoch_seed(chain_id: &ChainId) -> [u8; 32] {
    let mut epoch_seed: [u8; 32] =
        Hash::new(format!("iroha:localnet:npos-epoch-seed:v1:{chain_id}")).into();
    if epoch_seed == [0; 32] {
        epoch_seed[0] = 1;
    }
    epoch_seed
}
fn apply_localnet_npos_overrides(
    parameters: &mut Parameters,
    chain_id: &ChainId,
    peers: NonZeroU16,
) -> Result<()> {
    let mut npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .unwrap_or_default();
    // The signed election ceiling must match the roster used to size ingress capacity.
    // A future larger committee requires an explicit capacity and parameter update.
    npos.max_validators = u32::from(peers.get());
    // Use an explicit small self bond for disposable localnet allocations.
    npos.min_self_bond = 1_u64.into();
    npos.epoch_seed = localnet_npos_epoch_seed(chain_id);
    parameters.set_parameter(Parameter::Custom(npos.into_custom_parameter()));
    Ok(())
}
fn localnet_custom_parameter_id(name: &str) -> CustomParameterId {
    CustomParameterId::new(
        name.parse()
            .expect("constant custom parameter name is valid"),
    )
}
fn localnet_ivm_gas_units_per_gas_payload(asset: &str) -> Json {
    let payload = format!(
        concat!(
            r#"[{{"asset":"{asset}","#,
            r#""liquidity_profile":"tier2","#,
            r#""twap_local_per_xor":"1","#,
            r#""units_per_gas":{units},"#,
            r#""volatility_class":"stable"}}]"#
        ),
        asset = asset,
        units = LOCALNET_IVM_GAS_UNITS_PER_GAS
    );
    Json::from_str_norito(&payload).expect("localnet gas-rate payload must be valid JSON")
}
fn apply_localnet_ivm_gas_limit_override(parameters: &mut Parameters) {
    let gas_param_id = localnet_custom_parameter_id("ivm_gas_limit_per_block");
    let gas_param = CustomParameter::new(gas_param_id, Json::new(LOCALNET_IVM_GAS_LIMIT_PER_BLOCK));
    parameters.set_parameter(Parameter::Custom(gas_param));
}
fn apply_localnet_ivm_gas_fee_overrides(parameters: &mut Parameters) {
    let fee_asset_id = localnet_xor_asset_literal();
    let accepted_assets = CustomParameter::new(
        localnet_custom_parameter_id("ivm_gas_accepted_assets"),
        Json::new(vec![fee_asset_id.clone()]),
    );
    parameters.set_parameter(Parameter::Custom(accepted_assets));
    let units_per_gas = CustomParameter::new(
        localnet_custom_parameter_id("ivm_gas_units_per_gas"),
        localnet_ivm_gas_units_per_gas_payload(&fee_asset_id),
    );
    parameters.set_parameter(Parameter::Custom(units_per_gas));
}
fn localnet_npos_stake_amount(parameters: &Parameters, requested: Option<u64>) -> Result<Quantity> {
    let requested = Quantity::from(requested.unwrap_or(LOCALNET_STAKE_AMOUNT));
    let min_self_bond = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .map_or_else(|| requested.clone(), |params| params.min_self_bond);
    Ok(requested.max(min_self_bond).max(Quantity::from(1_u64)))
}
fn append_localnet_private_root_admission_policy(
    genesis: RawGenesisTransaction,
    chain_id: &str,
) -> Result<RawGenesisTransaction> {
    // Parent admission is explicitly enabled only on disposable global localnets.
    // Public Taira requires its own qualified operator release; child roots cannot
    // admit descendants through the global parent registry.
    if chain_id == PUBLIC_TAIRA_CHAIN_ID
        || genesis.sumeragi_context_parameters().root_scope != SumeragiRootScope::Global
    {
        return Ok(genesis);
    }
    let policy = PrivateDataspaceAdmissionPolicy {
        max_registered_roots: 64,
        max_roots_per_owner: 8,
    };
    genesis
        .into_builder()
        .append_parameter(Parameter::Custom(policy.into_custom_parameter()?))
        .build_raw()
}

fn apply_parameter_overrides(
    genesis: RawGenesisTransaction,
    peers: NonZeroU16,
    block_cadence_ms: Option<u64>,
    block_max_transactions: u64,
    consensus_mode: SumeragiConsensusMode,
) -> Result<RawGenesisTransaction> {
    let include_npos = matches!(consensus_mode, SumeragiConsensusMode::Npos);
    let mut parameters = genesis
        .effective_parameters()
        .wrap_err("generated localnet genesis must have one structured parameter block")?;
    let fee_asset_id = localnet_xor_asset_literal();
    let gas_limit_param_id = localnet_custom_parameter_id("ivm_gas_limit_per_block");
    let block_max_transactions =
        NonZeroU64::new(block_max_transactions).expect("block_max_transactions must be non-zero");
    let gas_fee_params_need_update = if include_npos {
        let accepted_assets_param_id = localnet_custom_parameter_id("ivm_gas_accepted_assets");
        let units_per_gas_param_id = localnet_custom_parameter_id("ivm_gas_units_per_gas");
        let accepted_assets_payload = Json::new(vec![fee_asset_id.clone()]);
        let units_per_gas_payload = localnet_ivm_gas_units_per_gas_payload(&fee_asset_id);
        parameters
            .custom()
            .get(&accepted_assets_param_id)
            .map(CustomParameter::payload)
            != Some(&accepted_assets_payload)
            || parameters
                .custom()
                .get(&units_per_gas_param_id)
                .map(CustomParameter::payload)
                != Some(&units_per_gas_payload)
    } else {
        false
    };
    let should_update = block_cadence_ms.is_some()
        || include_npos
        || parameters
            .custom()
            .get(&gas_limit_param_id)
            .and_then(|custom| custom.payload().try_into_any_norito::<u64>().ok())
            != Some(LOCALNET_IVM_GAS_LIMIT_PER_BLOCK)
        || gas_fee_params_need_update
        || parameters.block.max_transactions != block_max_transactions;
    if !should_update {
        return Ok(genesis);
    }
    parameters.block.max_transactions = block_max_transactions;
    if let Some(block_cadence_ms) = block_cadence_ms {
        parameters.sumeragi.block_cadence_ms =
            NonZeroU64::new(block_cadence_ms).expect("validated non-zero block cadence");
    }
    if include_npos {
        apply_localnet_npos_overrides(&mut parameters, genesis.chain_id(), peers)?;
    }
    apply_localnet_ivm_gas_limit_override(&mut parameters);
    if include_npos {
        apply_localnet_ivm_gas_fee_overrides(&mut parameters);
    }
    let mut builder = genesis.into_builder();
    if let Some(block_cadence_ms) = block_cadence_ms {
        builder = builder.with_block_cadence_ms(
            NonZeroU64::new(block_cadence_ms).expect("validated non-zero block cadence"),
        );
    }
    let pending_parameters = parameters.parameters().collect::<Vec<_>>();
    if !pending_parameters.is_empty() {
        for parameter in pending_parameters {
            builder = builder.append_parameter(parameter);
        }
    }
    builder.build_raw()
}
fn apply_localnet_crypto_overrides(
    genesis: RawGenesisTransaction,
) -> Result<RawGenesisTransaction> {
    let mut crypto = genesis.crypto().clone();
    if !crypto
        .allowed_signing
        .iter()
        .any(|algo| matches!(algo, iroha_crypto::Algorithm::BlsNormal))
    {
        crypto
            .allowed_signing
            .push(iroha_crypto::Algorithm::BlsNormal);
    }
    crypto.allowed_signing.sort();
    crypto.allowed_signing.dedup();
    crypto.allowed_curve_ids = crypto
        .allowed_signing
        .iter()
        .filter_map(|algo| {
            iroha_data_model::account::curve::CurveId::try_from_algorithm(*algo).ok()
        })
        .map(iroha_data_model::account::curve::CurveId::as_u8)
        .collect();
    crypto.allowed_curve_ids.sort_unstable();
    crypto.allowed_curve_ids.dedup();
    genesis.into_builder().with_crypto(crypto).build_raw()
}
fn append_peer_pop(
    genesis: RawGenesisTransaction,
    peers: &[Peer],
) -> Result<RawGenesisTransaction> {
    let mut topology = peers
        .iter()
        .map(|peer| {
            GenesisTopologyEntry::new(PeerId::new(peer.public_key.clone()), peer.bls_pop.clone())
        })
        .collect::<Vec<_>>();
    topology.sort_by(|left, right| left.peer.cmp(&right.peer));
    genesis
        .into_builder()
        .next_transaction()
        .set_topology(topology)
        .build_raw()
}
/// Sign the native lane policy of a multi-lane Global catalog into the genesis parameters.
///
/// Every non-zero catalog lane becomes a fixed native lane of its catalog dataspace, served by
/// the complete genesis topology (canonical committee order, genesis PoPs). Only the catalog's
/// account-matcher routes are carried over; instruction-only routes are not, and a dataspace
/// without an account route (the Public BPNG dataspace) routes by target dataspace. Without
/// this policy a dataspace-targeted transaction has no execution route, and light clients
/// refuse a genesis that does not set exactly one policy (`verify_genesis_dataspace_v1`).
/// Single-lane catalogs and private roots are unchanged.
fn append_localnet_native_lane_policy(
    genesis: RawGenesisTransaction,
    nexus: &actual::Nexus,
) -> Result<RawGenesisTransaction> {
    use iroha_data_model::sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
    };
    let context = genesis.sumeragi_context_parameters();
    let mut lanes = nexus
        .lane_catalog
        .lanes()
        .iter()
        .filter(|lane| lane.id != LaneId::new(0))
        .map(|lane| (lane.id, lane.dataspace_id))
        .collect::<Vec<_>>();
    if lanes.is_empty() || context.root_scope != SumeragiRootScope::Global {
        return Ok(genesis);
    }
    lanes.sort_unstable();
    let parameters = genesis
        .effective_parameters()
        .wrap_err("generated localnet genesis must have one structured parameter block")?;
    ensure!(
        !parameters
            .custom()
            .contains_key(&SumeragiLanePolicy::parameter_id()),
        "generated localnet genesis already sets a native lane policy"
    );
    let mut pops = std::collections::BTreeMap::new();
    for entry in genesis.transactions().iter().flat_map(|tx| tx.topology()) {
        let pop = entry.pop_bytes()?.ok_or_else(|| {
            eyre!(
                "genesis topology peer {} has no proof of possession",
                entry.peer
            )
        })?;
        ensure!(
            pops.insert(entry.peer.clone(), pop).is_none(),
            "genesis topology repeats peer {}",
            entry.peer
        );
    }
    ensure!(
        !pops.is_empty(),
        "native lane policy requires a genesis topology"
    );
    let committee = iroha_core::sumeragi::schedule::canonical_committee(pops.keys().cloned())
        .map_err(|error| eyre!("genesis topology is not a native lane committee: {error}"))?
        .into_iter()
        .map(|peer| SumeragiLaneMember {
            pop: pops
                .remove(&peer)
                .expect("canonical committee keeps topology peers"),
            peer,
        })
        .collect::<Vec<_>>();
    let mut policy = SumeragiLanePolicy::for_chain(parameters.sumeragi.clone(), context.da_layout);
    policy.fixed = lanes
        .into_iter()
        .map(|(lane, dataspace)| SumeragiFixedLane {
            lane,
            dataspace,
            committee: committee.clone(),
        })
        .collect();
    policy.routes = nexus
        .routing_policy
        .rules
        .iter()
        .filter(|rule| rule.matcher.account.is_some())
        .map(|rule| SumeragiLaneRoute {
            lane: rule.lane,
            account: rule.matcher.account.clone(),
            instruction: rule.matcher.instruction.clone(),
        })
        .collect();
    iroha_core::sumeragi::lanes::step::validate_policy(&policy)
        .map_err(|error| eyre!("generated native lane policy is invalid: {error}"))?;
    genesis
        .into_builder()
        .append_parameter(Parameter::Custom(policy.into_custom_parameter()))
        .build_raw()
}
#[cfg(test)]
fn append_localnet_contract_permissions(
    genesis: RawGenesisTransaction,
    genesis_account_id: &AccountId,
) -> RawGenesisTransaction {
    append_localnet_contract_permissions_for_client(
        genesis,
        genesis_account_id,
        &localnet_client_account_id(),
    )
    .expect("rebuilding a generated localnet fixture preserves explicit genesis authority")
}
fn append_localnet_service_accounts(
    genesis: RawGenesisTransaction,
    service_accounts: &[iroha_data_model::account::NewAccount],
) -> Result<RawGenesisTransaction> {
    let mut registered = genesis
        .instructions()
        .filter_map(|instruction| {
            let register = instruction.as_any().downcast_ref::<RegisterBox>()?;
            let RegisterBox::Account(register) = register else {
                return None;
            };
            Some(register.object.id.clone())
        })
        .collect::<BTreeSet<_>>();
    // Generated account/asset custody leaves its global phase open. Service
    // registration and its following fee/contract grants share that authority.
    let mut builder = genesis.into_builder();
    for account in service_accounts {
        if registered.insert(account.id.clone()) {
            builder = builder.append_instruction(Register::account(account.clone()));
        }
    }
    builder.build_raw()
}
fn append_localnet_service_fee_bootstrap(
    genesis: RawGenesisTransaction,
    genesis_account_id: &AccountId,
    operator_account_id: &AccountId,
    onboarding_account_id: &AccountId,
) -> Result<RawGenesisTransaction> {
    let mut registrations = BootstrapRegistrations::from_manifest(&genesis);
    let universal_domain = DomainId::parse_fully_qualified(LOCALNET_UNIVERSAL_DOMAIN)
        .expect("static universal domain must remain canonical");
    let fee_asset_id = localnet_xor_asset_definition_id();
    // Continue the service-account transaction: these universal fee instructions consume
    // those accounts, and sharing their boundary keeps staged genesis within the protocol cap.
    let mut builder = genesis.into_builder();
    if registrations.domains.insert(universal_domain.clone()) {
        builder = builder.append_instruction(Register::domain(Domain::new(universal_domain)));
    }
    if registrations.asset_defs.insert(fee_asset_id.clone()) {
        let definition = AssetDefinition::new(
            fee_asset_id.clone(),
            "XOR".to_owned(),
            NumericSpec::fractional(LOCALNET_FEE_ASSET_SCALE),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .with_metadata(Metadata::default());
        builder = builder.append_instruction(Register::asset_definition(definition));
    }
    builder = builder.append_instruction(SetAssetDefinitionAlias::bind(
        fee_asset_id.clone(),
        crate::genesis::PUBLIC_XOR_ALIAS
            .parse()
            .expect("canonical XOR alias"),
        None,
    ));
    builder = builder.append_instruction(Mint::asset_quantity(
        LOCALNET_ALIAS_SETUP_PAYER_BALANCE,
        AssetId::new(fee_asset_id.clone(), genesis_account_id.clone()),
    ));
    if operator_account_id != genesis_account_id {
        let operator_fee_asset = AssetId::new(fee_asset_id.clone(), operator_account_id.clone());
        builder = builder.append_instruction(Mint::asset_quantity(
            LOCALNET_ALIAS_SETUP_PAYER_BALANCE,
            operator_fee_asset,
        ));
    }
    if onboarding_account_id != genesis_account_id && onboarding_account_id != operator_account_id {
        builder = builder.append_instruction(Mint::asset_quantity(
            LOCALNET_ALIAS_SETUP_PAYER_BALANCE,
            AssetId::new(fee_asset_id.clone(), onboarding_account_id.clone()),
        ));
    }
    // Both Permissioned and NPoS public localnets expose this exact operator as
    // their funded faucet authority. Allocate the service balances before the
    // consensus-specific bootstrap so a default Permissioned network can serve
    // its advertised claim without granting runtime minting permission.
    builder = builder.append_instruction(Mint::asset_quantity(
        LOCALNET_FAUCET_AUTHORITY_BALANCE,
        AssetId::new(fee_asset_id.clone(), operator_account_id.clone()),
    ));
    if onboarding_account_id != operator_account_id {
        builder = builder.append_instruction(Mint::asset_quantity(
            LOCALNET_FAUCET_AUTHORITY_BALANCE,
            AssetId::new(fee_asset_id, onboarding_account_id.clone()),
        ));
    }
    builder.build_raw()
}
fn localnet_alias_setup_request(
    genesis_account_id: &AccountId,
    operator_account_id: &AccountId,
    taira: bool,
) -> Result<AliasSetupPlanRequestV1> {
    let dataspace_id = DataSpaceId::UNIVERSAL;
    let dataspace = ResolvedDataSpaceV1::new("universal".parse()?, dataspace_id);
    let domain_name = if taira {
        TAIRA_CANARY_DOMAIN
    } else {
        CLIENT_ACCOUNT_DOMAIN
    };
    let operator_alias = if taira {
        TAIRA_LOCALNET_OPERATOR_ALIAS
    } else {
        LOCALNET_OPERATOR_ALIAS
    };
    let domain = ResolvedDomainV1::new(DomainId::parse_fully_qualified(domain_name)?, dataspace_id);
    let alias =
        ResolvedAccountAliasV1::new(operator_alias.parse::<AccountAliasName>()?, dataspace_id);
    let guard = AliasQuoteGuardV1 {
        expected_policy_version: LOCALNET_ALIAS_SETUP_POLICY_VERSION,
        expected_payment_asset: localnet_xor_asset_definition_id(),
        max_amount: Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE),
        valid_until_ms: u64::MAX,
    };
    let acquisition = AliasLeaseAcquisitionV1::new(1, None);
    Ok(AliasSetupPlanRequestV1::new(vec![
        EnsureAlias::new(
            AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
                dataspace,
                owner: genesis_account_id.clone(),
            }),
            acquisition,
            guard.clone(),
        ),
        EnsureAlias::new(
            AliasIntentV1::Domain(AliasDomainIntentV1 {
                domain,
                owner: genesis_account_id.clone(),
            }),
            acquisition,
            guard.clone(),
        ),
        EnsureAlias::new(
            AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                alias,
                target_account: operator_account_id.clone(),
                provision: AccountProvisionV1::Existing,
                role: AccountAliasRoleV1::Primary,
            }),
            acquisition,
            guard,
        ),
    ]))
}
fn append_localnet_alias_setup(
    genesis: RawGenesisTransaction,
    request: &AliasSetupPlanRequestV1,
    append_to_current_transaction: bool,
) -> Result<RawGenesisTransaction> {
    let mut builder = genesis.into_builder();
    if !append_to_current_transaction {
        builder = builder.next_transaction();
    }
    for ensure in request.intents.iter().cloned() {
        builder = builder.append_instruction(ensure);
    }
    builder.build_raw()
}
fn write_localnet_alias_setup_intent(
    out_dir: &Path,
    request: &AliasSetupPlanRequestV1,
) -> Result<PathBuf> {
    let path = out_dir.join(LOCALNET_ALIAS_SETUP_INTENT_FILE);
    let json = norito::json::to_json_pretty(request)
        .wrap_err("encode generated alias setup intent as canonical JSON")?;
    custody::write(&path, json)
        .wrap_err_with(|| format!("write generated alias setup intent {}", path.display()))?;
    Ok(path)
}
fn append_localnet_onboarding_permissions(
    genesis: RawGenesisTransaction,
    onboarding_account_id: &AccountId,
    taira: bool,
) -> Result<RawGenesisTransaction> {
    let domain = DomainId::parse_fully_qualified(if taira {
        TAIRA_CANARY_DOMAIN
    } else {
        CLIENT_ACCOUNT_DOMAIN
    })?;
    let manage_scope = if taira {
        AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL)
    } else {
        AccountAliasPermissionScope::Domain(domain.clone())
    };
    let permissions = [
        Permission::from(CanManageAccountAlias {
            scope: manage_scope,
        }),
        Permission::from(CanRegisterAccount {
            domain: domain.clone(),
        }),
        Permission::from(CanPublishSpaceDirectoryManifestForAccountDomain {
            dataspace: DataSpaceId::UNIVERSAL,
            domain,
        }),
    ];
    let mut existing = genesis
        .instructions()
        .filter_map(|instruction| {
            let grant = instruction.as_any().downcast_ref::<GrantBox>()?;
            let GrantBox::Permission(grant) = grant else {
                return None;
            };
            Some((grant.destination().clone(), grant.object().clone()))
        })
        .collect::<BTreeSet<_>>();
    // Alias setup has already materialized the target domain in this transaction. Keep the
    // dependent onboarding grants after those intents so strict domain resolution succeeds.
    let mut builder = genesis.into_builder();
    for permission in permissions {
        if existing.insert((onboarding_account_id.clone(), permission.clone())) {
            builder = builder.append_instruction(Grant::account_permission(
                permission,
                onboarding_account_id.clone(),
            ));
        }
    }
    builder.build_raw()
}
fn append_localnet_contract_permissions_for_client(
    genesis: RawGenesisTransaction,
    genesis_account_id: &AccountId,
    client_account_id: &AccountId,
) -> Result<RawGenesisTransaction> {
    let enact_governance: Permission = CanEnactGovernance.into();
    let manage_verifying_keys = Permission::new("CanManageVerifyingKeys".into(), Json::new(()));
    let manage_account_alias: Permission = CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
    }
    .into();
    let publish_manifest: Permission = CanPublishSpaceDirectoryManifest {
        dataspace: DataSpaceId::UNIVERSAL,
    }
    .into();
    let mut seen: BTreeSet<(AccountId, Permission)> = genesis
        .instructions()
        .filter_map(|instruction| {
            let grant = instruction.as_any().downcast_ref::<GrantBox>()?;
            let GrantBox::Permission(grant_permission) = grant else {
                return None;
            };
            Some((
                grant_permission.destination().clone(),
                grant_permission.object().clone(),
            ))
        })
        .collect();
    let mut grants = Vec::new();
    let mut push_unique = |permission: Permission, destination: AccountId| {
        if seen.insert((destination.clone(), permission.clone())) {
            grants.push((permission, destination));
        }
    };
    push_unique(enact_governance, client_account_id.clone());
    // Only the generated runtime operator controls privileged contract-code administration.
    // Registered builders publish immutable code with normal fees and no management grant.
    push_unique(CanManageSmartContractCode.into(), client_account_id.clone());
    push_unique(
        CanGrantSmartContractCodeManagement.into(),
        client_account_id.clone(),
    );
    push_unique(CanSetParameters.into(), client_account_id.clone());
    push_unique(CanSetHijiriParameters.into(), client_account_id.clone());
    push_unique(CanReadAllLedgerData.into(), client_account_id.clone());
    push_unique(
        Permission::new("CanManageSoracloud".into(), Json::new(())),
        client_account_id.clone(),
    );
    push_unique(manage_verifying_keys.clone(), genesis_account_id.clone());
    push_unique(manage_verifying_keys, client_account_id.clone());
    push_unique(manage_account_alias, client_account_id.clone());
    push_unique(publish_manifest, client_account_id.clone());
    let mut builder = genesis.into_builder();
    for (permission, destination) in grants {
        builder = builder.append_instruction(Grant::account_permission(permission, destination));
    }
    builder.build_raw()
}
struct BootstrapRegistrations {
    domains: BTreeSet<DomainId>,
    accounts: BTreeSet<AccountId>,
    asset_defs: BTreeSet<AssetDefinitionId>,
    zk_assets: BTreeSet<AssetDefinitionId>,
    verifying_keys: BTreeSet<VerifyingKeyId>,
}
impl BootstrapRegistrations {
    fn from_manifest(manifest: &RawGenesisTransaction) -> Self {
        let mut domains = BTreeSet::new();
        let mut accounts = BTreeSet::new();
        let mut asset_defs = BTreeSet::new();
        let mut zk_assets = BTreeSet::new();
        let mut verifying_keys = BTreeSet::new();
        for instruction in manifest.instructions() {
            if let Some(register) = instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::zk::RegisterZkAsset>()
            {
                zk_assets.insert(register.asset().clone());
                continue;
            }
            if let Some(register) = instruction
                .as_any()
                .downcast_ref::<verifying_keys::RegisterVerifyingKey>()
            {
                verifying_keys.insert(register.id.clone());
                continue;
            }
            let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() else {
                continue;
            };
            match register {
                RegisterBox::Domain(register) => {
                    domains.insert(register.object.id.clone());
                }
                RegisterBox::Account(register) => {
                    accounts.insert(register.object.id.clone());
                }
                RegisterBox::AssetDefinition(register) => {
                    asset_defs.insert(register.object.id.clone());
                }
                _ => {}
            }
        }
        Self {
            domains,
            accounts,
            asset_defs,
            zk_assets,
            verifying_keys,
        }
    }
}
struct LocalnetNposBootstrapContext<'a> {
    peers: &'a [Peer],
    gas_account_id: &'a AccountId,
    stake_amount: &'a Quantity,
    sora_profile: Option<SoraProfile>,
    genesis_account_id: &'a AccountId,
    client_account_id: &'a AccountId,
    onboarding_account_id: &'a AccountId,
    taira: bool,
}
fn append_localnet_npos_bootstrap(
    genesis: RawGenesisTransaction,
    context: &LocalnetNposBootstrapContext<'_>,
) -> Result<RawGenesisTransaction> {
    let peers = context.peers;
    let gas_account_id = context.gas_account_id;
    let stake_amount = context.stake_amount;
    let sora_profile = context.sora_profile;
    let genesis_account_id = context.genesis_account_id;
    let client_account_id = context.client_account_id;
    let onboarding_account_id = context.onboarding_account_id;
    let taira = context.taira;
    let nexus_domain = DomainId::parse_fully_qualified(LOCALNET_NEXUS_DOMAIN)?;
    let ivm_domain = DomainId::parse_fully_qualified(LOCALNET_IVM_DOMAIN)?;
    let universal_domain = DomainId::parse_fully_qualified(LOCALNET_UNIVERSAL_DOMAIN)?;
    let stake_asset_id = localnet_xor_asset_definition_id();
    let fee_asset_id = localnet_xor_asset_definition_id();
    let public_validator_lanes = localnet_public_validator_lanes(sora_profile, taira);
    let lane_count = u64::try_from(public_validator_lanes.len())
        .expect("public validator lane count must fit in u64");
    let stake_mint_amount = stake_amount
        .try_mul_decimal(&Numeric::from(lane_count))
        .map_err(|error| eyre!("localnet validator stake mint amount overflow: {error}"))?;
    let mut registrations = BootstrapRegistrations::from_manifest(&genesis);
    let mut builder = genesis.into_builder().next_transaction();
    if !registrations.domains.contains(&nexus_domain) {
        builder = builder.append_instruction(Register::domain(Domain::new(nexus_domain.clone())));
        registrations.domains.insert(nexus_domain.clone());
    }
    if !registrations.domains.contains(&ivm_domain) {
        builder = builder.append_instruction(Register::domain(Domain::new(ivm_domain.clone())));
        registrations.domains.insert(ivm_domain.clone());
    }
    if !registrations.domains.contains(&universal_domain) {
        builder =
            builder.append_instruction(Register::domain(Domain::new(universal_domain.clone())));
        registrations.domains.insert(universal_domain.clone());
    }
    if !registrations.accounts.contains(gas_account_id) {
        builder =
            builder.append_instruction(Register::account(Account::new(gas_account_id.clone())));
        registrations.accounts.insert(gas_account_id.clone());
    }
    if !registrations.asset_defs.contains(&stake_asset_id) {
        let definition = AssetDefinition::new(
            stake_asset_id.clone(),
            "XOR".to_owned(),
            NumericSpec::fractional(LOCALNET_FEE_ASSET_SCALE),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .with_metadata(Metadata::default());
        builder = builder.append_instruction(Register::asset_definition(definition));
        registrations.asset_defs.insert(stake_asset_id.clone());
    }
    if !registrations.asset_defs.contains(&fee_asset_id) {
        let definition = AssetDefinition::new(
            fee_asset_id.clone(),
            "XOR".to_owned(),
            NumericSpec::fractional(LOCALNET_FEE_ASSET_SCALE),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .with_metadata(Metadata::default());
        builder = builder.append_instruction(Register::asset_definition(definition));
        registrations.asset_defs.insert(fee_asset_id.clone());
    }
    let fee_vk_unshield_id = localnet_fee_vk_unshield_id();
    for (id, record) in localnet_confidential_fee_vk_registrations()? {
        if registrations.verifying_keys.insert(id.clone()) {
            builder =
                builder.append_instruction(verifying_keys::RegisterVerifyingKey { id, record });
        }
    }
    if !registrations.zk_assets.contains(&fee_asset_id) {
        builder = builder.append_instruction(iroha_data_model::isi::zk::RegisterZkAsset::new(
            fee_asset_id.clone(),
            Some(fee_vk_unshield_id),
        ));
        registrations.zk_assets.insert(fee_asset_id.clone());
    }
    for peer in peers {
        let validator_id = peer.validator_account_id(taira);
        if !registrations.accounts.contains(&validator_id) {
            builder =
                builder.append_instruction(Register::account(Account::new(validator_id.clone())));
            registrations.accounts.insert(validator_id.clone());
        }
        builder = builder.append_instruction(Mint::asset_quantity(
            stake_mint_amount.clone(),
            AssetId::new(stake_asset_id.clone(), validator_id.clone()),
        ));
        builder = builder.append_instruction(Mint::asset_quantity(
            stake_amount.clone(),
            AssetId::new(fee_asset_id.clone(), validator_id.clone()),
        ));
    }
    if !registrations.accounts.contains(client_account_id) {
        builder =
            builder.append_instruction(Register::account(Account::new(client_account_id.clone())));
        registrations.accounts.insert(client_account_id.clone());
    }
    if !registrations.accounts.contains(onboarding_account_id) {
        builder = builder.append_instruction(Register::account(Account::new(
            onboarding_account_id.clone(),
        )));
        registrations.accounts.insert(onboarding_account_id.clone());
    }
    let fee_sponsor_program_id = localnet_fee_sponsor_program_id(genesis_account_id);
    let fee_sponsor_revision =
        localnet_fee_sponsor_revision(fee_sponsor_program_id.clone(), fee_asset_id.clone());
    fee_sponsor_revision
        .validate()
        .map_err(|error| eyre!("invalid localnet fee sponsor revision: {error}"))?;
    builder = builder.append_instruction(Mint::asset_quantity(
        LOCALNET_FEE_SPONSOR_VAULT_BALANCE,
        AssetId::new(fee_asset_id.clone(), genesis_account_id.clone()),
    ));
    builder = builder.append_instruction(CreateFeeSponsorProgram {
        program: FeeSponsorProgram::new(fee_sponsor_program_id.clone(), genesis_account_id.clone()),
    });
    builder = builder.append_instruction(StageFeeSponsorProgramRevision {
        revision: fee_sponsor_revision,
    });
    builder = builder.append_instruction(EnrollFeeSponsorBeneficiary {
        program_id: fee_sponsor_program_id.clone(),
        beneficiary: client_account_id.clone(),
    });
    if onboarding_account_id != client_account_id {
        builder = builder.append_instruction(EnrollFeeSponsorBeneficiary {
            program_id: fee_sponsor_program_id.clone(),
            beneficiary: onboarding_account_id.clone(),
        });
    }
    builder = builder.append_instruction(FundFeeSponsorProgram {
        program_id: fee_sponsor_program_id.clone(),
        asset_definition_id: fee_asset_id,
        amount: Quantity::from(LOCALNET_FEE_SPONSOR_VAULT_BALANCE),
    });
    builder = builder.append_instruction(ActivateFeeSponsorProgramRevision {
        program_id: fee_sponsor_program_id.clone(),
        revision: 1,
        activate_at_height: 1,
    });
    let enroll_permission = CanEnrollFeeSponsorProgram {
        program_id: fee_sponsor_program_id,
    };
    builder = builder.append_instruction(Grant::account_permission(
        enroll_permission.clone(),
        client_account_id.clone(),
    ));
    if onboarding_account_id != client_account_id {
        builder = builder.append_instruction(Grant::account_permission(
            enroll_permission,
            onboarding_account_id.clone(),
        ));
    }
    if public_validator_lanes
        .iter()
        .any(|lane_id| *lane_id != LaneId::SINGLE)
    {
        // The same physical peers serve global and participant lanes. Publish
        // both purpose-specific key records before the participant registrations.
        builder = builder.append_instruction(Grant::account_permission(
            CanManageConsensusKeys,
            genesis_account_id.clone(),
        ));
        for peer in peers {
            let id = derive_committee_key_id(&peer.public_key);
            builder = builder.append_instruction(RegisterConsensusKey {
                id: id.clone(),
                record: ConsensusKeyRecord {
                    id,
                    public_key: peer.public_key.clone(),
                    pop: Some(peer.bls_pop.clone()),
                    activation_height: 1,
                    expiry_height: None,
                    replaces: None,
                    status: ConsensusKeyStatus::Active,
                },
            });
        }
        builder = builder.append_instruction(Revoke::account_permission(
            CanManageConsensusKeys,
            genesis_account_id.clone(),
        ));
    }
    append_public_lane_validator_registrations(
        builder,
        peers,
        &public_validator_lanes,
        &stake_asset_id,
        gas_account_id,
        stake_amount,
        taira,
    )
    .build_raw()
}
/// Permissioned localnets register the Nexus support accounts and every validator account, but
/// stake nothing: staking is NPoS-only (the network XOR identity lives in the signed NPoS
/// parameters), and the committee is the genesis roster (`RegisterPeerWithPop`).
fn append_localnet_permissioned_support_accounts(
    genesis: RawGenesisTransaction,
    peers: &[Peer],
    escrow_account_id: &AccountId,
    taira: bool,
) -> Result<RawGenesisTransaction> {
    let nexus_domain = DomainId::parse_fully_qualified(LOCALNET_NEXUS_DOMAIN)?;
    let registrations = BootstrapRegistrations::from_manifest(&genesis);
    let mut builder = genesis.into_builder().next_transaction();
    if !registrations.domains.contains(&nexus_domain) {
        builder = builder.append_instruction(Register::domain(Domain::new(nexus_domain)));
    }
    if !registrations.accounts.contains(escrow_account_id) {
        builder =
            builder.append_instruction(Register::account(Account::new(escrow_account_id.clone())));
    }
    for peer in peers {
        let validator_id = peer.validator_account_id(taira);
        if !registrations.accounts.contains(&validator_id) {
            builder = builder.append_instruction(Register::account(Account::new(validator_id)));
        }
    }
    builder.build_raw()
}
fn append_public_lane_validator_registrations(
    mut builder: GenesisBuilder,
    peers: &[Peer],
    lanes: &[LaneId],
    stake_asset_id: &AssetDefinitionId,
    escrow_account_id: &AccountId,
    stake_amount: &Quantity,
    taira: bool,
) -> GenesisBuilder {
    for &lane_id in lanes {
        // Universal registrations continue the universal funding/key bootstrap;
        // each non-universal participant retains a separate physical input.
        if lane_id != LaneId::SINGLE {
            builder = builder.next_transaction();
        }
        for peer in peers {
            let validator_id = peer.validator_account_id(taira);
            builder = builder.append_instruction(RegisterPublicLaneValidator {
                lane_id,
                validator: validator_id.clone(),
                peer_id: PeerId::from(peer.public_key.clone()),
                stake_account: validator_id.clone(),
                initial_stake: stake_amount.clone(),
                metadata: Metadata::default(),
                monetary_plan: PublicLaneMonetaryPlanV1::genesis_registration(
                    AssetId::new(stake_asset_id.clone(), validator_id.clone()),
                    AssetId::new(stake_asset_id.clone(), escrow_account_id.clone()),
                    stake_amount.clone(),
                ),
            });
            builder = builder.append_instruction(ActivatePublicLaneValidator {
                lane_id,
                validator: validator_id,
            });
        }
    }
    builder
}
#[allow(clippy::too_many_lines)]
fn append_private_dataspace_genesis_bootstrap_for_client(
    genesis: RawGenesisTransaction,
    sora_profile: Option<SoraProfile>,
    genesis_account_id: &AccountId,
    client_account_id: &AccountId,
) -> Result<RawGenesisTransaction> {
    let domains: &[&str] = match sora_profile {
        Some(SoraProfile::PrivateSbp) => SBP_BOOTSTRAP_DOMAINS,
        Some(SoraProfile::PrivateCbuae) => &[],
        Some(SoraProfile::PrivateBpng) => BPNG_BOOTSTRAP_DOMAINS,
        _ => return Ok(genesis),
    };
    let spec = private_dataspace_spec(sora_profile)
        .expect("private bootstrap profiles must have a private dataspace spec");
    let payment_amount: Quantity = LOCALNET_PRIVATE_SNS_LEASE_PAYMENT
        .parse()
        .map_err(|error| eyre!("invalid localnet private SNS lease payment: {error}"))?;
    let private_dataspace = DataSpaceId::new(spec.id);
    let acquisition = AliasLeaseAcquisitionV1::new(1, None);
    let quote_guard = AliasQuoteGuardV1 {
        expected_policy_version: LOCALNET_ALIAS_SETUP_POLICY_VERSION,
        expected_payment_asset: localnet_xor_asset_definition_id(),
        max_amount: payment_amount,
        valid_until_ms: u64::MAX,
    };
    let mut ensure_aliases = vec![EnsureAlias::new(
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(spec.alias.parse()?, private_dataspace),
            owner: client_account_id.clone(),
        }),
        acquisition,
        quote_guard.clone(),
    )];
    for domain in domains {
        ensure_aliases.push(EnsureAlias::new(
            AliasIntentV1::Domain(AliasDomainIntentV1 {
                domain: ResolvedDomainV1::new(
                    DomainId::parse_fully_qualified(domain)?,
                    private_dataspace,
                ),
                owner: client_account_id.clone(),
            }),
            acquisition,
            quote_guard.clone(),
        ));
    }
    // Genesis executes these private-resource intents under the genesis authority while
    // retaining the client as their explicit owner. Install only the exact scopes required
    // in an ephemeral role, then remove that role before the transaction commits. A direct
    // domain-scoped grant cannot bootstrap a missing domain because grant execution resolves
    // the domain before the following `EnsureAlias` has a chance to create it.
    let mut temporary_genesis_permissions = ensure_aliases
        .iter()
        .map(|ensure| match &ensure.intent {
            AliasIntentV1::Dataspace(intent) => Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(intent.dataspace.dataspace_id),
            }),
            AliasIntentV1::Domain(intent) => Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(intent.domain.canonical_name.clone()),
            }),
            AliasIntentV1::AccountAlias(_) => {
                unreachable!("private genesis bootstrap contains no account-alias intents")
            }
        })
        .collect::<Vec<_>>();
    let mut seen_permissions = BTreeSet::<(AccountId, Permission)>::new();
    // Genesis bootstrap also pre-seeds management scopes for registered account labels.
    // Treat those as pre-existing so cleanup never revokes authority the manifest already had.
    for instruction in genesis.instructions() {
        let Some(RegisterBox::Account(register)) =
            instruction.as_any().downcast_ref::<RegisterBox>()
        else {
            continue;
        };
        let Some(label) = register.object().label() else {
            continue;
        };
        if label.dataspace != private_dataspace {
            continue;
        }
        seen_permissions.insert((
            genesis_account_id.clone(),
            Permission::from(CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(private_dataspace),
            }),
        ));
        if let Some(domain) = &label.domain {
            seen_permissions.insert((
                genesis_account_id.clone(),
                Permission::from(CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Domain(DomainId::parse_fully_qualified(
                        &format!("{}.{}", domain.name(), spec.alias),
                    )?),
                }),
            ));
        }
    }
    // Apply explicit grants and revokes in manifest order on top of the pre-seeded label
    // scopes. This distinguishes authority that remains present from a historical grant that
    // was already revoked before the private bootstrap transaction.
    for instruction in genesis.instructions() {
        if let Some(GrantBox::Permission(grant)) = instruction.as_any().downcast_ref::<GrantBox>() {
            seen_permissions.insert((grant.destination().clone(), grant.object().clone()));
        }
        if let Some(RevokeBox::Permission(revoke)) =
            instruction.as_any().downcast_ref::<RevokeBox>()
        {
            seen_permissions.remove(&(revoke.destination().clone(), revoke.object().clone()));
        }
    }
    temporary_genesis_permissions.retain(|permission| {
        seen_permissions.insert((genesis_account_id.clone(), permission.clone()))
    });
    let temporary_genesis_role_id: RoleId = format!(
        "private_{}_dataspace_{}_alias_bootstrap",
        spec.alias,
        private_dataspace.as_u64()
    )
    .parse()
    .expect("private localnet aliases must produce a valid role id");
    if genesis.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterBox>()
            .is_some_and(|register| match register {
                RegisterBox::Role(register) => {
                    register.object().inner().id == temporary_genesis_role_id
                }
                _ => false,
            })
    }) {
        return Err(eyre!(
            "private-dataspace bootstrap refuses a pre-existing temporary setup role `{temporary_genesis_role_id}`"
        ));
    }
    let restricted_read_permission = Permission::from(CanReadRestrictedDataspace {
        dataspace: private_dataspace,
    });
    if seen_permissions.contains(&(
        client_account_id.clone(),
        restricted_read_permission.clone(),
    )) {
        return Err(eyre!(
            "private-dataspace bootstrap requires explicit restricted-read grants in both authorization worlds; refusing an ambiguous pre-existing grant for `{client_account_id}`"
        ));
    }
    let restricted_reader_role_id =
        crate::genesis::private_dataspace_reader_role_id(spec.alias, private_dataspace);
    if genesis.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterBox>()
            .is_some_and(|register| match register {
                RegisterBox::Role(register) => {
                    let role = register.object();
                    role.inner().id == restricted_reader_role_id
                        || role
                            .inner()
                            .permissions()
                            .any(|permission| permission == &restricted_read_permission)
                }
                _ => false,
            })
    }) {
        return Err(eyre!(
            "private-dataspace bootstrap refuses a pre-existing restricted-reader role for `{client_account_id}`"
        ));
    }
    let mut builder = genesis.into_builder().next_transaction();
    let temporary_genesis_role = temporary_genesis_permissions.iter().cloned().fold(
        Role::new(
            temporary_genesis_role_id.clone(),
            genesis_account_id.clone(),
        ),
        iroha_data_model::NewRole::add_permission,
    );
    builder = builder.append_instruction(Register::role(temporary_genesis_role));
    for ensure in ensure_aliases {
        builder = builder.append_instruction(ensure);
    }
    builder = builder.append_instruction(Unregister::role(temporary_genesis_role_id));
    builder = builder.append_instruction(Grant::account_permission(
        restricted_read_permission.clone(),
        client_account_id.clone(),
    ));
    let universal_permissions = vec![
        Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
        }),
        Permission::from(CanResolveAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(DataSpaceId::UNIVERSAL),
        }),
    ];
    let universal_permissions = universal_permissions
        .into_iter()
        .filter(|permission| {
            seen_permissions.insert((client_account_id.clone(), permission.clone()))
        })
        .collect::<Vec<_>>();
    // Keep the universal ingress role and ancillary universal permissions separate from the
    // private EnsureAlias transaction so the router never collapses either authorization world
    // into the universal coordinator. The private world receives the direct grant above, while
    // Torii's universal ingress hop reads the same capability from this native role.
    builder = builder
        .next_transaction()
        .append_instruction(Register::role(
            Role::new(restricted_reader_role_id, client_account_id.clone())
                .add_permission(restricted_read_permission),
        ));
    for permission in universal_permissions {
        builder = builder.append_instruction(Grant::account_permission(
            permission,
            client_account_id.clone(),
        ));
    }
    builder.build_raw()
}
struct GenesisConsensusPolicies {
    da_proof_policies: Option<DaProofPolicyBundle>,
    confidential_policy_hash: [u8; 32],
}
struct GenesisWriteContext<'a> {
    creation_time_ms: Option<u64>,
    manifest: &'a RawGenesisTransaction,
    public_key: &'a iroha_crypto::PublicKey,
    private_key: ExposedPrivateKey,
    config: &'a actual::Root,
    chain_discriminant: Option<u16>,
    json_path: &'a Path,
    signed_path: &'a Path,
    policies: GenesisConsensusPolicies,
}
fn write_genesis(context: GenesisWriteContext<'_>) -> Result<HashOf<BlockHeader>> {
    let GenesisWriteContext {
        creation_time_ms,
        manifest,
        public_key,
        private_key,
        config,
        chain_discriminant,
        json_path,
        signed_path,
        policies,
    } = context;
    let chain_discriminant =
        chain_discriminant.unwrap_or_else(iroha_data_model::account::address::chain_discriminant);
    let genesis = manifest.clone().with_chain_discriminant(chain_discriminant);
    let _chain_discriminant = Some(ChainDiscriminantGuard::enter(chain_discriminant));
    let json = norito::json::to_json_pretty(&genesis)?;
    validate_genesis_manifest_json(json.as_bytes())
        .wrap_err("generated genesis.json exceeds fixed resource bounds")?;
    custody::write(json_path, json).wrap_err("failed to write genesis.json")?;
    drop(genesis);
    // Sign the exact persisted manifest. Custom JSON parameter payloads can have a different
    // textual key order before and after the manifest's JSON round trip; signing the reloaded
    // form keeps genesis.json and genesis.signed.nrt semantically and canonically aligned.
    let persisted_genesis = RawGenesisTransaction::from_path(json_path)
        .wrap_err("failed to reload persisted genesis.json before signing")?;
    let genesis_key_pair =
        KeyPair::new(public_key.clone(), private_key.0).wrap_err("make genesis key pair")?;
    let (bound_manifest, block, nexus_context) =
        crate::genesis::staging::bind_and_sign_staged_sumeragi_context_with_preimage(
            persisted_genesis,
            &genesis_key_pair,
            Some(config),
            policies.da_proof_policies,
            policies.confidential_policy_hash,
            creation_time_ms,
        )
        .wrap_err("stage and sign genesis block")?;
    let mut bound_json =
        norito::json::to_json_pretty(&bound_manifest).wrap_err("encode bound genesis manifest")?;
    bound_json.push('\n');
    validate_genesis_manifest_json(bound_json.as_bytes())
        .wrap_err("bound genesis.json exceeds fixed resource bounds")?;
    custody::replace(json_path, bound_json).wrap_err("write bound genesis.json")?;
    drop(bound_manifest);
    let expected_hash = block.0.hash();
    let framed = block.0.encode_wire().wrap_err("frame genesis block")?;
    drop(block);
    if framed.len() > SIGNED_GENESIS_MAX_BYTES_V1 {
        return Err(eyre!(
            "generated signed genesis body is {} bytes, exceeding the {}-byte first-release limit",
            framed.len(),
            SIGNED_GENESIS_MAX_BYTES_V1
        ));
    }
    custody::write(signed_path, &framed)?;
    custody::write(
        &signed_path.with_file_name("nexus-amx-context.v1.bin"),
        &nexus_context,
    )?;
    Ok(expected_hash)
}
fn write_and_validate_genesis_expected_hash(
    expected_hash_path: &Path,
    signed_path: &Path,
    expected_hash: HashOf<BlockHeader>,
) -> Result<()> {
    let decoded = read_signed_genesis(signed_path)
        .wrap_err("read and decode the generated signed genesis body")?;
    if decoded.hash() != expected_hash {
        return Err(eyre!(
            "generated signed genesis body hashes to {}, expected {}",
            decoded.hash(),
            expected_hash
        ));
    }
    let network_id = NetworkId::from_genesis_hash(expected_hash);
    let record = format!("{network_id}\n");
    write_owner_only_localnet_file(expected_hash_path, record.as_bytes()).wrap_err_with(|| {
        format!(
            "write checked genesis network identity file {}",
            expected_hash_path.display()
        )
    })?;
    let persisted = fs::read_to_string(expected_hash_path).wrap_err_with(|| {
        format!(
            "read checked genesis network identity file {}",
            expected_hash_path.display()
        )
    })?;
    if persisted != record {
        return Err(eyre!(
            "persisted genesis network identity file is not the canonical generated record"
        ));
    }
    let parsed = persisted
        .strip_suffix('\n')
        .expect("canonical record always ends in a newline")
        .parse::<NetworkId>()
        .wrap_err("parse persisted checked genesis network identity")?;
    if parsed != network_id {
        return Err(eyre!(
            "persisted genesis network identity changed from {network_id} to {parsed}"
        ));
    }
    Ok(())
}
fn write_genesis_key_files(
    public_path: &Path,
    private_path: &Path,
    public_key: &iroha_crypto::PublicKey,
    private_key: &ExposedPrivateKey,
) -> Result<()> {
    let canonical = Zeroizing::new(
        private_key
            .try_to_multihash_string()
            .wrap_err("encode genesis private key")?,
    );
    let mut raw = Zeroizing::new(Vec::with_capacity(canonical.len() + 1));
    raw.extend_from_slice(canonical.as_bytes());
    raw.push(b'\n');
    crate::localnet::custody::write_private_file_atomic(private_path, raw.as_slice())
        .wrap_err("write genesis private key")?;
    let mut public = public_key.to_string();
    public.push('\n');
    custody::write(public_path, public.as_bytes())
        .wrap_err_with(|| format!("write genesis public-key file {}", public_path.display()))
}
pub(crate) fn parse_localnet_peer_config(
    rendered_config: &str,
    config_path: Option<&Path>,
) -> Result<actual::Root> {
    let description = config_path.map_or_else(
        || "generated localnet bootstrap config".to_owned(),
        |path| format!("generated peer config {}", path.display()),
    );
    let table = crate::secret_toml::parse_table(rendered_config, &description)?;
    // Scope validation to the chain used to render account-typed fields.
    let chain_discriminant = table
        .get("chain_discriminant")
        .and_then(toml::Value::as_integer)
        .and_then(|value| u16::try_from(value).ok());
    let _chain_discriminant = chain_discriminant.map(ChainDiscriminantGuard::enter);
    if table.contains_key("data_dir") {
        use iroha_config::node_config::{NodeConfigOptions, NodeFile, open_node_config};
        let path = config_path
            .ok_or_else(|| eyre!("managed node configuration requires its absolute source path"))?;
        let node = open_node_config(
            NodeFile::Verified {
                path: path.to_path_buf(),
                table,
            },
            NodeConfigOptions::default(),
        )
        .map_err(|_| {
            eyre!("generated managed node configuration has an invalid data_dir layout")
        })?;
        let (user, _) = node
            .read()
            .map_err(|_| eyre!("generated managed node configuration is invalid"))?;
        return user
            .parse()
            .map_err(|_| eyre!("generated managed node configuration fails validation"));
    }
    let source = TomlSource::new_sensitive(
        config_path.map_or_else(
            || PathBuf::from("generated:localnet-bootstrap-config"),
            Path::to_path_buf,
        ),
        table,
        crate::secret_toml::zeroize_table,
    );
    actual::Root::from_toml_source(source).map_err(|error| {
        eyre!(
            "generated peer config is invalid while deriving consensus policies: {}",
            generated_config_error_categories(&error)
        )
    })
}

// Only typed schema/validation categories and fixed public schema names are diagnostics.
// Report attachments, source paths and arbitrary ParameterId strings may contain private values.
fn generated_config_error_categories<E>(error: &error_stack::Report<E>) -> String
where
    E: std::error::Error + Send + Sync + 'static,
{
    use iroha_config::{base::read, parameters::user::ParseError};
    let mut categories = Vec::new();
    for frame in error.frames() {
        let category = frame
            .downcast_ref::<ParseError>()
            .map(ToString::to_string)
            .or_else(|| {
                frame.downcast_ref::<read::Error>().map(|error| {
                    match error {
                        read::Error::ReadFile => "configuration source could not be read",
                        read::Error::InSourceFile(_) => "configuration source is invalid",
                        read::Error::InvalidExtends | read::Error::CannotExtend => {
                            "configuration extension is invalid"
                        }
                        read::Error::ParseParameter(id) => {
                            return generated_config_parameter_name(id).map_or_else(
                                || "a configuration parameter could not be parsed".to_owned(),
                                |name| {
                                    format!("configuration parameter `{name}` could not be parsed")
                                },
                            );
                        }
                        read::Error::InEnvironment => "configuration environment is invalid",
                        read::Error::MissingParameters => {
                            "required configuration fields are missing"
                        }
                        read::Error::UnknownParameters => {
                            "configuration contains unrecognised fields"
                        }
                    }
                    .to_owned()
                })
            });
        if let Some(category) = category {
            if !categories.contains(&category) {
                categories.push(category);
                if categories.len() == 8 {
                    break;
                }
            }
        }
    }
    if categories.is_empty() {
        "configuration validation failed".to_owned()
    } else {
        categories.join("; ")
    }
}

// Compare complete typed paths, then render only these literals. ParameterId is publicly
// constructible, so neither its Display nor a path supplied by a report is safe to print.
fn generated_config_parameter_name(id: &iroha_config::base::ParameterId) -> Option<String> {
    const FIELDS: &[(&[&str], &[&str])] = &[
        (
            &[],
            &[
                "chain",
                "chain_discriminant",
                "private_key",
                "public_key",
                "soranet_transport_private_key",
                "soranet_transport_public_key",
                "trusted_peers",
                "trusted_peers_pop",
                "telemetry_profile",
            ],
        ),
        (&["kura"], &["store_dir", "fsync_mode"]),
        (
            &["soracloud_runtime"],
            &[
                "state_dir",
                "production_mode",
                "hydration_concurrency",
                "prepared_runtime_cache_capacity",
            ],
        ),
        (
            &["soracloud_runtime", "submission"],
            &["fee_payer", "signer"],
        ),
        (
            &["soracloud_runtime", "egress"],
            &[
                "default_allow",
                "allowed_hosts",
                "rate_per_minute",
                "max_bytes_per_minute",
            ],
        ),
        (&["tiered_state"], &["cold_store_root", "da_store_root"]),
        (&["sumeragi"], &["role", "records_dir", "installation_log"]),
        (&["sumeragi", "keys"], &["allowed_algorithms"]),
        (
            &["nexus"],
            &[
                "lane_count",
                "lane_catalog",
                "dataspace_catalog",
                "routing_policy",
            ],
        ),
        (
            &["nexus", "storage"],
            &[
                "local_budget_bytes",
                "max_wsv_memory_bytes",
                "disk_budget_weights",
            ],
        ),
        (&["nexus", "fusion"], &["exit_teu"]),
        (
            &["nexus", "staking"],
            &[
                "stake_asset_id",
                "stake_escrow_account_id",
                "slash_sink_account_id",
            ],
        ),
        (
            &["nexus", "fees"],
            &[
                "fee_asset_id",
                "base_fee",
                "per_byte_fee",
                "per_instruction_fee",
                "per_gas_unit_fee",
                "settlement_mode",
                "fee_sink_account_id",
                "sponsor_vault_custody_account_id",
            ],
        ),
        (&["nexus", "registry"], &["manifest_directory"]),
        (&["nexus", "governance"], &["default_module", "modules"]),
        (
            &["pipeline"],
            &["signature_batch_max_ed25519", "signature_batch_max_bls"],
        ),
        (&["pipeline", "gas"], &["tech_account_id"]),
        (
            &["queue"],
            &[
                "capacity",
                "capacity_per_user",
                "transaction_time_to_live_ms",
            ],
        ),
        (&["crypto"], &["allowed_signing"]),
        (&["crypto", "curves"], &["allowed_curve_ids"]),
        (
            &["streaming"],
            &[
                "identity_public_key",
                "identity_private_key",
                "session_store_dir",
            ],
        ),
        (
            &["streaming", "codec"],
            &[
                "cabac_mode",
                "trellis_blocks",
                "rans_tables_path",
                "entropy_mode",
                "bundle_width",
                "bundle_accel",
            ],
        ),
        (
            &["sorafs", "storage"],
            &["enabled", "data_dir", "max_capacity_bytes"],
        ),
        (&["sorafs", "por"], &["state_dir"]),
        (
            &["gov"],
            &[
                "citizenship_escrow_account",
                "bond_escrow_account",
                "slash_receiver_account",
                "viral_incentive_pool_account",
                "viral_escrow_account",
                "sorafs_pin_fee_treasury_account",
                "sorafs_provider_owners",
            ],
        ),
        (&["gov", "sorafs_telemetry"], &["submitters"]),
        (&["confidential"], &["enabled", "assume_valid"]),
        (
            &["genesis"],
            &["file", "public_key", "expected_hash", "expected_hash_file"],
        ),
        (&["logger"], &["format", "level", "filter"]),
        (
            &["network"],
            &[
                "address",
                "public_address",
                "max_total_connections",
                "p2p_subscriber_queue_cap",
                "max_frame_bytes",
                "max_frame_bytes_consensus",
                "max_frame_bytes_control",
                "max_frame_bytes_block_sync",
                "max_frame_bytes_tx_gossip",
                "max_frame_bytes_peer_gossip",
                "max_frame_bytes_health",
                "max_frame_bytes_other",
                "consensus_ingress_rate_per_sec",
                "consensus_ingress_burst",
                "consensus_ingress_bytes_per_sec",
                "consensus_ingress_bytes_burst",
                "transaction_gossip_period_ms",
                "transaction_gossip_resend_ticks",
                "transaction_gossip_public_target_reshuffle_ms",
                "transaction_gossip_restricted_target_reshuffle_ms",
            ],
        ),
        (
            &["network", "soranet_handshake", "pow"],
            &["revocation_store_path"],
        ),
        (&["network", "soranet_vpn"], &["operator_account_id"]),
        (
            &["torii"],
            &[
                "address",
                "data_dir",
                "peer_telemetry_urls",
                "preauth_allow_cidrs",
                "preauth_rate_per_ip_per_sec",
                "preauth_burst_per_ip",
                "api_rate_limit_bypass_cidrs",
                "internal_api_trusted_cidrs",
                "tx_rate_per_authority_per_sec",
                "tx_burst_per_authority",
                "api_high_load_tx_threshold",
                "max_content_len",
                "zk_prover_enabled",
            ],
        ),
        (
            &["torii", "operator_signatures"],
            &["enabled", "allowed_public_keys"],
        ),
        (
            &["torii", "da_ingest"],
            &["replay_cache_store_dir", "manifest_store_dir"],
        ),
        (
            &["torii", "mcp"],
            &[
                "enabled",
                "profile",
                "expose_operator_routes",
                "allow_tool_prefixes",
            ],
        ),
        (
            &["torii", "account_onboarding"],
            &[
                "authority",
                "private_key_file",
                "lease_term_years",
                "additional_permissions",
                "credentials",
                "fee_sponsor_program_id",
            ],
        ),
        (
            &["torii", "faucet"],
            &[
                "enabled",
                "authority",
                "private_key_file",
                "asset_definition_id",
                "amount",
                "pow_difficulty_bits",
                "pow_scrypt_log_n",
                "pow_scrypt_r",
                "pow_scrypt_p",
                "pow_max_anchor_age_blocks",
                "pow_adaptive_lookback_blocks",
                "pow_adaptive_claims_per_extra_bit",
                "pow_adaptive_max_extra_bits",
                "pow_beacon_seed_enabled",
            ],
        ),
        (
            &["torii", "transport", "https"],
            &[
                "address",
                "certificate_chain",
                "private_key",
                "handshake_timeout_ms",
            ],
        ),
        (
            &["torii", "transport", "norito_rpc"],
            &["enabled", "require_mtls", "stage", "allowed_clients"],
        ),
    ];
    FIELDS.iter().find_map(|(prefix, fields)| {
        fields.iter().find_map(|field| {
            let candidate = iroha_config::base::ParameterId::from(
                prefix.iter().copied().chain(std::iter::once(*field)),
            );
            (id == &candidate).then(|| {
                prefix
                    .iter()
                    .copied()
                    .chain(std::iter::once(*field))
                    .collect::<Vec<_>>()
                    .join(".")
            })
        })
    })
}

#[cfg(test)]
mod config_error_tests {
    use super::generated_config_error_categories;
    use error_stack::Report;
    use iroha_config::{
        base::read,
        parameters::{actual, user::ParseError},
    };

    #[test]
    fn typed_validation_category_never_renders_private_report_attachments() {
        let report = Report::new(ParseError::InvalidStreamingConfig)
            .attach("private-key-and-credential-value-must-remain-hidden")
            .change_context(actual::FromTomlSourceError);
        assert_eq!(
            generated_config_error_categories(&report),
            "Invalid streaming configuration"
        );
        let unknown = Report::new(std::io::Error::other("private source path and secret"))
            .attach("private credential")
            .change_context(actual::FromTomlSourceError);
        assert_eq!(
            generated_config_error_categories(&unknown),
            "configuration validation failed"
        );
    }

    #[test]
    fn schema_read_category_is_visible_without_paths_or_values() {
        let report = Report::new(read::Error::UnknownParameters)
            .attach("private configuration field and value")
            .change_context(actual::FromTomlSourceError);
        assert_eq!(
            generated_config_error_categories(&report),
            "configuration contains unrecognised fields"
        );
        let report = Report::new(read::Error::ParseParameter(["private_key"].into()))
            .attach("private key value")
            .change_context(actual::FromTomlSourceError);
        assert_eq!(
            generated_config_error_categories(&report),
            "configuration parameter `private_key` could not be parsed"
        );
    }

    #[test]
    fn only_exact_public_schema_paths_are_rendered() {
        let report = Report::new(read::Error::ParseParameter(["network", "address"].into()))
            .attach("private address value")
            .change_context(read::Error::InSourceFile("/private/secret.toml".into()))
            .change_context(actual::FromTomlSourceError);
        assert_eq!(
            generated_config_error_categories(&report),
            "configuration source is invalid; configuration parameter `network.address` could not be parsed"
        );
        let report = Report::new(read::Error::ParseParameter(
            ["confidential", "enabled"].into(),
        ))
        .attach("private configuration value")
        .change_context(actual::FromTomlSourceError);
        assert_eq!(
            generated_config_error_categories(&report),
            "configuration parameter `confidential.enabled` could not be parsed"
        );
        for id in [
            ["zk", "pipa_r", "enabled"].into(),
            ["zk", "halo2", "enabled"].into(),
            ["network.address"].into(),
            ["private-secret-value"].into(),
            ["network", "private-secret-value"].into(),
        ] {
            let report = Report::new(read::Error::ParseParameter(id))
                .attach("private key value")
                .change_context(actual::FromTomlSourceError);
            assert_eq!(
                generated_config_error_categories(&report),
                "a configuration parameter could not be parsed"
            );
        }
        assert_eq!(
            generated_config_error_categories(&Report::new(read::Error::ReadFile)),
            "configuration source could not be read"
        );
    }
}

/// Validate an isolated post-DKG Taira launch without changing its initial configuration.
///
/// Only the native reader handles configuration and credential bodies. The public result
/// binds the checked configuration hash and retained filesystem identities for an opaque
/// FD 198/200 handoff by the generated launcher.
///
/// # Errors
/// Refuses unsafe paths or custody, changed node settings, mismatched beacon shares, and
/// occupied or overlapping private loopback listeners.
pub fn validate_beacon_launch(
    network_dir: &Path,
    peer_index: u16,
    beacon_config: &Path,
    beacon_credential: &Path,
) -> Result<norito::json::Value> {
    #[cfg(not(unix))]
    {
        let _ = (network_dir, peer_index, beacon_config, beacon_credential);
        Err(eyre!(
            "Taira private beacon launch requires native Unix descriptor custody"
        ))
    }
    #[cfg(unix)]
    {
        use iroha_core::beacon::credential::MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1;
        use std::net::SocketAddr as NativeSocketAddr;

        ensure!(
            peer_index < 4,
            "private Taira launch requires a four-peer index"
        );
        ensure!(
            network_dir.is_absolute(),
            "network directory must be absolute"
        );
        let network = iroha_fs::PrivateDirectory::open(network_dir)?;
        ensure!(
            network.path() == network_dir && fs::canonicalize(network_dir)? == network_dir,
            "network directory must be canonical"
        );
        let seat = private_beacon_seat(network_dir, beacon_config, beacon_credential)?;

        let initial_path = network_dir.join(format!("peer{peer_index}.toml"));
        let (initial_bytes, initial_identity) =
            read_beacon_launch_input(&initial_path, 1024 * 1024)?;
        let (beacon_bytes, beacon_identity) = read_beacon_launch_input(beacon_config, 1024 * 1024)?;
        let initial_text = std::str::from_utf8(&initial_bytes)
            .map_err(|_| eyre!("initial config is not UTF-8"))?;
        let beacon_text =
            std::str::from_utf8(&beacon_bytes).map_err(|_| eyre!("beacon config is not UTF-8"))?;
        validate_beacon_config_projection(initial_text, beacon_text)?;
        let initial = parse_localnet_peer_config(initial_text, Some(&initial_path))?;
        let projected = parse_localnet_peer_config(beacon_text, Some(beacon_config))?;
        ensure!(
            initial.common.chain.to_string() == PUBLIC_TAIRA_CHAIN_ID
                && *initial.common.chain_discriminant.value() == 369,
            "private beacon launch requires the native Taira profile"
        );
        ensure!(
            initial.common.peer.id() == projected.common.peer.id()
                && initial.genesis.expected_hash == projected.genesis.expected_hash,
            "beacon projection changed the peer or genesis identity"
        );

        let mut addresses = Vec::new();
        let mut generated_roster = BTreeSet::new();
        for index in 0..4 {
            let path = network_dir.join(format!("peer{index}.toml"));
            let bytes = iroha_fs::read_private(&path, 1024 * 1024)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| eyre!("initial peer config is not UTF-8"))?;
            let peer = parse_localnet_peer_config(text, Some(&path))?;
            ensure!(
                peer.common.chain == initial.common.chain
                    && peer.genesis.expected_hash == initial.genesis.expected_hash,
                "private Taira peers must share one exact genesis identity"
            );
            validate_private_beacon_state(&peer, network_dir, index)?;
            ensure!(
                generated_roster.insert(peer.common.peer.id().clone()),
                "private Taira peers must have distinct validator identities"
            );
            let mut peer_addresses = Vec::new();
            for listener in [peer.network.address.value(), peer.torii.address.value()] {
                let address = listener
                    .to_string()
                    .parse::<NativeSocketAddr>()
                    .map_err(|_| {
                        eyre!("private beacon launch requires numeric loopback listeners")
                    })?;
                peer_addresses.push(address);
            }
            addresses.push([peer_addresses[0], peer_addresses[1]]);
        }
        // Retain both reservations until validation finishes, so the listeners cannot collide
        // with each other during the native preflight. Startup performs the actual bind.
        let _reservations = reserve_private_beacon_listeners(&addresses, usize::from(peer_index))?;

        let provider = &projected.sumeragi;
        let handle = provider
            .global_beacon_partial_signer_provider_handle
            .as_deref()
            .ok_or_else(|| eyre!("beacon projection omits its native provider"))?;
        let revision = provider
            .global_beacon_partial_signer_provider_revision
            .ok_or_else(|| eyre!("beacon projection omits its provider revision"))?;
        let digest = provider
            .global_beacon_partial_signer_provider_policy_digest
            .ok_or_else(|| eyre!("beacon projection omits its provider policy digest"))?;
        let network_id = NetworkId::from_genesis_hash(initial.genesis.expected_hash);
        let genesis_path = network_dir.join("genesis.signed.nrt");
        ensure!(
            initial.genesis.file.as_ref().map(|file| file.value()) == Some(&genesis_path),
            "private Taira genesis must remain inside this generated network"
        );
        let genesis = read_signed_genesis(&genesis_path)?;
        ensure!(
            genesis.hash() == initial.genesis.expected_hash,
            "private Taira signed genesis differs from its native configuration anchor"
        );
        let roster = iroha_core::sumeragi::startup::genesis_committee_peers(&genesis)?;
        ensure!(
            roster.len() == 4
                && roster.iter().cloned().collect::<BTreeSet<_>>() == generated_roster,
            "private Taira config identities differ from the exact genesis roster"
        );
        let expected_session = iroha_data_model::consensus::GlobalThresholdBeaconDkgSessionV1 {
            version: iroha_data_model::consensus::GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id,
            session_id: iroha_core::beacon::ceremony::global_beacon_genesis_session_id_v1(
                network_id,
            ),
            attempt_id: iroha_core::beacon::ceremony::global_beacon_genesis_attempt_id_v1(
                network_id,
            ),
            authority_generation: 0,
            roster_hash: iroha_core::beacon::global_threshold_beacon_roster_hash_v1(&roster),
            committee_size: 4,
            threshold: 2,
            start_height: 1,
            commitments_end_height: 2,
            deliveries_end_height: 3,
            acceptances_end_height: 4,
        };
        let (credential_bytes, credential_identity) = read_beacon_launch_input(
            beacon_credential,
            MAX_CONSENSUS_THRESHOLD_CREDENTIAL_BYTES_V1,
        )?;
        // One pool belongs to this launch operation and its parsed public policy. Imported
        // session owners retain this pool until the complete seat validation finishes.
        let credential_budget = iroha_core::state::AllocationBudget::new(
            projected
                .runtime_provider_broker
                .credential_max_memory_bytes
                .get(),
        );
        validate_beacon_credential_seat(
            &credential_budget,
            &credential_bytes,
            &network_id,
            handle,
            revision,
            digest,
            initial.common.peer.id(),
            seat,
            &expected_session,
        )?;

        let signer_path = network_dir
            .join("runtime")
            .join(TAIRA_RUNTIME_SIGNER_DIRECTORY)
            .join(format!("peer{peer_index}.private_key"));
        let (signer, signer_identity) = read_beacon_launch_input(&signer_path, 71)?;
        ensure!(
            signer.len() == 71,
            "runtime signer requires its exact canonical record"
        );
        let signer_text =
            std::str::from_utf8(&signer).map_err(|_| eyre!("runtime signer is not UTF-8"))?;
        let signer_key: ExposedPrivateKey = signer_text
            .strip_suffix('\n')
            .ok_or_else(|| eyre!("runtime signer omits its canonical newline"))?
            .parse()
            .map_err(|_| eyre!("runtime signer is not a native private key"))?;
        let signer_key = KeyPair::from_private_key(signer_key.0)?;
        let (_, public_bytes) = signer_key.public_key().try_to_bytes()?;
        let table = crate::secret_toml::Table::new(crate::secret_toml::parse_table(
            initial_text,
            "initial config",
        )?);
        ensure!(
            table
                .get("soracloud_runtime")
                .and_then(|value| value.get("submission"))
                .and_then(|value| value.get("signer"))
                .and_then(|value| value.get("public_key_hex"))
                .and_then(toml::Value::as_str)
                == Some(hex::encode(public_bytes).as_str()),
            "runtime signer does not match this peer's native provider"
        );
        network.revalidate()?;
        let beacon_config_path = beacon_config.to_path_buf();
        let credential_path = beacon_credential.to_path_buf();
        let config_blake3 = blake3::hash(&beacon_bytes).to_hex().to_string();
        let signer_size = signer.len();
        let credential_size = credential_bytes.len();
        let result = norito::json!({
            "schema": "iroha.taira.private-beacon-launch.v1",
            "peer_index": peer_index,
            "initial_config": initial_path,
            "initial_identity": initial_identity,
            "beacon_config": beacon_config_path,
            "beacon_identity": beacon_identity,
            "config_blake3": config_blake3,
            "sources": [
                {"descriptor": 198, "path": signer_path, "size": signer_size, "identity": signer_identity},
                {"descriptor": 200, "path": credential_path, "size": credential_size, "identity": credential_identity}
            ]
        });
        ensure!(
            norito::json::to_vec(&result)?.len() <= 16384,
            "public launch selection exceeds its bound"
        );
        Ok(result)
    }
}

#[cfg(unix)]
fn validate_private_beacon_state(
    config: &actual::Root,
    network: &Path,
    peer_index: usize,
) -> Result<()> {
    let paths = LocalnetPeerStoragePaths::new(network, peer_index);
    let records = paths.state.join(LOCALNET_SUMERAGI_RECORDS_DIR);
    let installation = paths.state.join(LOCALNET_SUMERAGI_INSTALLATION_LOG);
    ensure!(
        config.data_dir.is_none()
            && config.kura.store_dir.value() == &paths.kura
            && config.sumeragi.records_dir == records
            && config.sumeragi.installation_log == installation
            && config.soracloud_runtime.state_dir == paths.soracloud_runtime
            && config.tiered_state.cold_store_root.as_ref() == Some(&paths.tiered_state)
            && config.tiered_state.da_store_root.as_ref() == Some(&paths.da_store)
            && config.streaming.session_store_dir == paths.streaming_sessions
            && config
                .network
                .soranet_handshake
                .pow
                .revocation_store_path
                .as_ref()
                == paths.soranet_ticket_revocations.to_string_lossy()
            && config.torii.data_dir == paths.torii
            && config.torii.da_ingest.replay_cache_store_dir == paths.torii_da_replay_cache
            && config.torii.da_ingest.manifest_store_dir == paths.torii_da_manifests
            && config.torii.sorafs_storage.data_dir == paths.sorafs
            && config.torii.sorafs_por.state_dir == paths.sorafs_por
            && config.snapshot.store_dir.value() == &paths.kura.join("snapshot"),
        "private Taira state paths must match this generated peer's isolated roots"
    );
    // Some optional workers create descendants only at first use. Validate each existing
    // ancestry through native no-follow custody, including paths that will later be created.
    for directory in [
        &paths.kura,
        &paths.state,
        &records,
        &paths.soracloud_runtime,
        &paths.tiered_state,
        &paths.da_store,
        &paths.streaming_sessions,
        &paths.torii,
        &paths.torii_da_replay_cache,
        &paths.torii_da_manifests,
        &paths.sorafs,
        &paths.sorafs_por,
        &paths.kura.join("snapshot"),
        &paths.state.join("snapshot"),
    ] {
        validate_private_beacon_ancestry(directory)?;
    }
    for file in [&installation, &paths.soranet_ticket_revocations] {
        let parent = file
            .parent()
            .ok_or_else(|| eyre!("private state file has no parent"))?;
        validate_private_beacon_ancestry(parent)?;
        match fs::symlink_metadata(file) {
            Ok(_) => {
                let owner = iroha_fs::PrivateDirectory::open(parent)?;
                let descriptor = owner.open_read(
                    file.file_name()
                        .ok_or_else(|| eyre!("private state file has no name"))?,
                )?;
                iroha_fs::FileSnapshot::of(&descriptor, true)?;
                owner.revalidate()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_beacon_ancestry(path: &Path) -> Result<()> {
    let mut existing = path;
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => return Ok(iroha_fs::PrivateDirectory::open(existing)?.revalidate()?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing = existing
                    .parent()
                    .ok_or_else(|| eyre!("private state path has no existing ancestor"))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(unix)]
fn private_beacon_seat(network_dir: &Path, beacon_config: &Path, credential: &Path) -> Result<u16> {
    let run = network_dir
        .parent()
        .ok_or_else(|| eyre!("network directory has no private run root"))?;
    let seat_dir = beacon_config
        .parent()
        .ok_or_else(|| eyre!("beacon config has no seat directory"))?;
    let seat = seat_dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("seat-"))
        .and_then(|seat| seat.parse::<u16>().ok())
        .filter(|seat| (1..=4).contains(seat))
        .ok_or_else(|| eyre!("beacon config requires an exact seat-1..4 directory"))?;
    ensure!(
        network_dir.is_absolute()
            && seat_dir == run.join("beacon").join(format!("seat-{seat}"))
            && beacon_config == seat_dir.join("beacon.toml")
            && credential == seat_dir.join("iroha-global-beacon-partial-signer-v1.norito"),
        "beacon inputs must belong to this isolated run's exact seat directory"
    );
    Ok(seat)
}

#[cfg(unix)]
fn reserve_private_beacon_listeners(
    addresses: &[[std::net::SocketAddr; 2]],
    peer_index: usize,
) -> Result<Vec<std::net::TcpListener>> {
    ensure!(
        addresses.len() == 4 && peer_index < 4,
        "private Taira listener selection requires exactly four peers"
    );
    let mut ports = BTreeSet::new();
    for address in addresses.iter().flatten() {
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "private beacon launch requires non-zero loopback listeners"
        );
        ensure!(
            ports.insert(address.port()),
            "private peer listener ports overlap"
        );
    }
    addresses[peer_index]
        .iter()
        .map(|address| {
            std::net::TcpListener::bind(address)
                .map_err(|_| eyre!("private peer listener is already occupied"))
        })
        .collect()
}

#[cfg(unix)]
fn validate_beacon_credential_seat(
    budget: &iroha_core::state::AllocationBudget,
    bytes: &[u8],
    network_id: &NetworkId,
    handle: &str,
    revision: u64,
    digest: [u8; 32],
    peer: &PeerId,
    seat: u16,
    expected_session: &iroha_data_model::consensus::GlobalThresholdBeaconDkgSessionV1,
) -> Result<()> {
    let shares =
        iroha_core::beacon::credential::decode_global_beacon_partial_signer_credential_shares_v1(
            bytes, network_id, handle, revision, digest, budget,
        )
        .map_err(|_| eyre!("beacon credential does not authenticate this provider and network"))?;
    ensure!(
        shares.len() == 1,
        "fresh private beacon launch requires one native key session"
    );
    let share = &shares[0];
    ensure!(
        share.public_session().adaptive_dkg.session == *expected_session
            && share.public_session().network_id == *network_id
            && share.public_session().session_id == expected_session.session_id
            && share.public_session().committee_size == 4
            && share.public_session().threshold == 2,
        "beacon credential differs from the exact fresh four-validator genesis session"
    );
    let recipient = share
        .public_session()
        .adaptive_dkg
        .recipient_keys
        .iter()
        .find(|recipient| recipient.recipient_index == share.signer_index())
        .ok_or_else(|| eyre!("beacon credential omits its signer roster entry"))?;
    ensure!(
        share.signer_index() == seat && &recipient.validator == peer,
        "beacon credential belongs to a different validator seat"
    );
    Ok(())
}

fn validate_beacon_config_projection(initial: &str, projected: &str) -> Result<()> {
    let original =
        crate::secret_toml::Table::new(crate::secret_toml::parse_table(initial, "initial config")?);
    let mut beacon = crate::secret_toml::Table::new(crate::secret_toml::parse_table(
        projected,
        "beacon config",
    )?);
    ensure!(
        !original.contains_key("extends") && !beacon.contains_key("extends"),
        "private beacon configs must be flattened"
    );
    let original_sumeragi = original
        .get("sumeragi")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| eyre!("initial config omits sumeragi"))?;
    let beacon_sumeragi = beacon
        .get_mut("sumeragi")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| eyre!("beacon config omits sumeragi"))?;
    for field in [
        "global_beacon_partial_signer_provider_handle",
        "global_beacon_partial_signer_provider_revision",
        "global_beacon_partial_signer_provider_policy_digest_hex",
    ] {
        ensure!(
            !original_sumeragi.contains_key(field) && beacon_sumeragi.contains_key(field),
            "private beacon projection requires exactly the new provider binding"
        );
        crate::secret_toml::remove(beacon_sumeragi, field);
    }
    ensure!(
        *original == *beacon,
        "beacon projection changed initial node settings"
    );
    Ok(())
}

#[cfg(unix)]
fn read_beacon_launch_input(
    path: &Path,
    maximum: usize,
) -> Result<(Zeroizing<Vec<u8>>, Vec<norito::json::Value>)> {
    use std::{io::Read as _, os::unix::fs::MetadataExt as _};
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "private launch input must use its canonical absolute path"
    );
    let parent = iroha_fs::PrivateDirectory::open(
        path.parent()
            .ok_or_else(|| eyre!("launch input has no parent"))?,
    )?;
    let name = path
        .file_name()
        .ok_or_else(|| eyre!("launch input has no name"))?;
    let mut file = parent.open_read(name)?;
    let snapshot = iroha_fs::FileSnapshot::of(&file, true)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.len() > 0 && metadata.len() <= maximum as u64,
        "private launch input exceeds its size bound"
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    parent.revalidate()?;
    ensure!(
        bytes.len() as u64 == metadata.len()
            && iroha_fs::FileSnapshot::of(&file, true)? == snapshot
            && iroha_fs::FileSnapshot::of(&parent.open_read(name)?, true)? == snapshot,
        "private launch input identity changed during native validation"
    );
    let nanos = |seconds: i64, fraction: i64| {
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(fraction))
            .ok_or_else(|| eyre!("native launch identity timestamp is out of range"))
    };
    let identity = vec![
        metadata.dev().into(),
        metadata.ino().into(),
        metadata.uid().into(),
        metadata.gid().into(),
        metadata.mode().into(),
        metadata.nlink().into(),
        metadata.len().into(),
        nanos(metadata.mtime(), metadata.mtime_nsec())?.into(),
        nanos(metadata.ctime(), metadata.ctime_nsec())?.into(),
    ];
    Ok((bytes, identity))
}

#[cfg(all(test, unix))]
mod private_beacon_launch_tests {
    use super::*;
    use std::{
        net::TcpListener,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    const INITIAL: &str = "# original bytes remain intact\nchain = 'taira'\n[network]\naddress = '127.0.0.1:18081'\n[sumeragi]\nrole = 'validator'\nsafety_records_dir = '/private/run/network/state/peer0/sumeragi-records'\n";

    fn projection() -> String {
        format!(
            "{INITIAL}global_beacon_partial_signer_provider_handle = 'software://iroha/beacon/seat-1'\nglobal_beacon_partial_signer_provider_revision = 1\nglobal_beacon_partial_signer_provider_policy_digest_hex = '{}'\n",
            "ab".repeat(32)
        )
    }

    #[test]
    fn separate_beacon_projection_preserves_initial_bytes_and_state() {
        let root = localnet_test_helpers::private_tempdir().unwrap();
        let initial = root.path().join("peer0.toml");
        custody::write(&initial, INITIAL.as_bytes()).unwrap();
        let before = fs::metadata(&initial).unwrap();
        let before_hash = blake3::hash(INITIAL.as_bytes());
        validate_beacon_config_projection(INITIAL, &projection()).unwrap();
        let (bytes, identity) = read_beacon_launch_input(&initial, 1024).unwrap();
        assert_eq!(bytes.as_slice(), INITIAL.as_bytes());
        assert_eq!(blake3::hash(&bytes), before_hash);
        assert_eq!(identity[0], norito::json::Value::from(before.dev()));
        assert_eq!(identity[1], norito::json::Value::from(before.ino()));
        assert_eq!(fs::metadata(&initial).unwrap().ino(), before.ino());
        for changed in [
            projection().replace("127.0.0.1:18081", "127.0.0.1:8080"),
            projection().replace("/private/run/network/state", "/var/lib/taira"),
            projection().replace("chain = 'taira'", "chain = 'other'"),
            projection().replace("role = 'validator'", "role = 'observer'"),
            format!("extends = 'other.toml'\n{}", projection()),
            INITIAL.to_owned(),
        ] {
            assert!(validate_beacon_config_projection(INITIAL, &changed).is_err());
        }
        assert!(validate_beacon_config_projection(&projection(), &projection()).is_err());
        assert_eq!(fs::read(&initial).unwrap(), INITIAL.as_bytes());
    }

    #[test]
    fn beacon_inputs_reject_other_run_seat_and_credential_paths() {
        let network = Path::new("/private/run/network");
        let config = Path::new("/private/run/beacon/seat-2/beacon.toml");
        let credential =
            Path::new("/private/run/beacon/seat-2/iroha-global-beacon-partial-signer-v1.norito");
        assert_eq!(private_beacon_seat(network, config, credential).unwrap(), 2);
        for config in [
            Path::new("/private/other/beacon/seat-2/beacon.toml"),
            Path::new("/private/run/beacon/seat-02/beacon.toml"),
            Path::new("/private/run/beacon/seat-0/beacon.toml"),
            Path::new("/private/run/beacon/seat-2/peer0.toml"),
            Path::new("/var/lib/taira/taira-validator-1/beacon.toml"),
        ] {
            assert!(private_beacon_seat(network, config, credential).is_err());
        }
        assert!(
            private_beacon_seat(
                network,
                config,
                Path::new(
                    "/private/run/beacon/seat-1/iroha-global-beacon-partial-signer-v1.norito"
                )
            )
            .is_err()
        );
        let root = localnet_test_helpers::private_tempdir().unwrap();
        let network = root.path().join("network");
        custody::ensure_directory(&network).unwrap();
        assert!(validate_beacon_launch(&network, 4, config, credential).is_err());
        assert!(validate_beacon_launch(&network, 0, config, credential).is_err());
    }

    #[test]
    fn private_beacon_listener_selection_rejects_collisions_and_public_binds() {
        let held = (0..8)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let mut addresses = held
            .chunks_exact(2)
            .map(|pair| [pair[0].local_addr().unwrap(), pair[1].local_addr().unwrap()])
            .collect::<Vec<_>>();
        assert!(
            reserve_private_beacon_listeners(&addresses, 0)
                .unwrap_err()
                .to_string()
                .contains("occupied")
        );
        addresses[1][0] = addresses[0][0];
        assert!(
            reserve_private_beacon_listeners(&addresses, 0)
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );
        addresses[1][0] = "0.0.0.0:1234".parse().unwrap();
        assert!(
            reserve_private_beacon_listeners(&addresses, 0)
                .unwrap_err()
                .to_string()
                .contains("loopback")
        );
        addresses[1][0] = held[2].local_addr().unwrap();
        drop(held);
        assert_eq!(
            reserve_private_beacon_listeners(&addresses, 0)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn beacon_credential_validation_rejects_malformed_native_frames() {
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([1; 32]),
        ));
        let peer = PeerId::new(REAL_GENESIS_ACCOUNT_KEYPAIR.public_key().clone());
        let expected_session = iroha_data_model::consensus::GlobalThresholdBeaconDkgSessionV1 {
            version: 1,
            network_id: network,
            session_id: [1; 32],
            attempt_id: [2; 32],
            authority_generation: 0,
            roster_hash: [3; 32],
            committee_size: 4,
            threshold: 2,
            start_height: 1,
            commitments_end_height: 2,
            deliveries_end_height: 3,
            acceptances_end_height: 4,
        };
        for bytes in [b"".as_slice(), b"not a native beacon credential".as_slice()] {
            assert!(
                validate_beacon_credential_seat(
                    &iroha_core::state::AllocationBudget::new(0),
                    bytes,
                    &network,
                    "software://iroha/beacon/seat-1",
                    1,
                    [2; 32],
                    &peer,
                    1,
                    &expected_session
                )
                .is_err()
            );
        }
    }

    #[test]
    fn native_launch_input_rejects_aliases_permissions_and_relative_paths() {
        let root = localnet_test_helpers::private_tempdir().unwrap();
        let source = root.path().join("source");
        let alias = root.path().join("alias");
        custody::write(&source, b"native source").unwrap();
        assert!(read_beacon_launch_input(&source, 3).is_err());
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(read_beacon_launch_input(&alias, 1024).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&source, &alias).unwrap();
        assert!(read_beacon_launch_input(&source, 1024).is_err());
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_beacon_launch_input(&source, 1024).is_err());
        assert!(read_beacon_launch_input(Path::new("source"), 1024).is_err());
    }

    #[test]
    fn private_beacon_state_rejects_serving_roots_and_linked_candidate_storage() {
        let _resources = crate::managed::native_test_guard();
        let root = localnet_test_helpers::private_tempdir().unwrap();
        let network = root.path().join("network");
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = prepare_localnet("local", &network, &ports).unwrap();
        let path = &prepared.peers[0].config_path;
        let bytes = iroha_fs::read_private(path, 1024 * 1024).unwrap();
        // The private beacon launcher selects the operator-owned generator layout.
        // Managed data_dir is deliberately refused rather than projected into serving roots.
        let managed =
            parse_localnet_peer_config(std::str::from_utf8(&bytes).unwrap(), Some(path)).unwrap();
        assert!(validate_private_beacon_state(&managed, &network, 0).is_err());
        let paths = LocalnetPeerStoragePaths::new(&network, 0);
        custody::ensure_directory(&paths.kura).unwrap();
        custody::ensure_directory(&paths.state).unwrap();
        let mut config = managed;
        config.data_dir = None;
        *config.kura.store_dir.value_mut() = paths.kura.clone();
        config.sumeragi.records_dir = paths.state.join(LOCALNET_SUMERAGI_RECORDS_DIR);
        config.sumeragi.installation_log = paths.state.join(LOCALNET_SUMERAGI_INSTALLATION_LOG);
        config.soracloud_runtime.state_dir = paths.soracloud_runtime.clone();
        config.tiered_state.cold_store_root = Some(paths.tiered_state.clone());
        config.tiered_state.da_store_root = Some(paths.da_store.clone());
        config.streaming.session_store_dir = paths.streaming_sessions.clone();
        config.network.soranet_handshake.pow.revocation_store_path = paths
            .soranet_ticket_revocations
            .to_string_lossy()
            .into_owned()
            .into();
        config.torii.data_dir = paths.torii.clone();
        config.torii.da_ingest.replay_cache_store_dir = paths.torii_da_replay_cache.clone();
        config.torii.da_ingest.manifest_store_dir = paths.torii_da_manifests.clone();
        config.torii.sorafs_storage.data_dir = paths.sorafs.clone();
        config.torii.sorafs_por.state_dir = paths.sorafs_por.clone();
        *config.snapshot.store_dir.value_mut() = paths.kura.join("snapshot");
        validate_private_beacon_state(&config, &network, 0).unwrap();
        config.sumeragi.records_dir = PathBuf::from("/var/lib/taira/serving/sumeragi-records");
        assert!(validate_private_beacon_state(&config, &network, 0).is_err());
        config.sumeragi.records_dir = paths.state.join(LOCALNET_SUMERAGI_RECORDS_DIR);
        std::os::unix::fs::symlink(&paths.state, &paths.soracloud_runtime).unwrap();
        assert!(validate_private_beacon_state(&config, &network, 0).is_err());
        fs::remove_file(&paths.soracloud_runtime).unwrap();
        validate_private_beacon_ancestry(&paths.state.join("future/child")).unwrap();
        fs::remove_dir(&paths.kura).unwrap();
        std::os::unix::fs::symlink(&paths.state, &paths.kura).unwrap();
        assert!(validate_private_beacon_state(&config, &network, 0).is_err());
    }

    #[test]
    fn private_beacon_launcher_hands_off_two_opaque_fds_and_rejects_changed_sources() {
        let root = localnet_test_helpers::private_tempdir().unwrap();
        for (name, bytes) in [
            ("initial.toml", b"initial exact bytes".as_slice()),
            ("beacon.toml", b"projected exact bytes".as_slice()),
            ("key", &[0x41; 71]),
            ("credential", &[0x43; 257]),
        ] {
            custody::write(root.path().join(name), bytes).unwrap();
        }
        let python = format!(
            "import errno\nimport os\nimport stat\nimport subprocess\nimport sys\n{TAIRA_RUNTIME_LAUNCH_PY}\n{}",
            r#"
root = sys.argv[1]
def capture_taira_start(*_args):
    pass
env = os.environ.copy()
env.update(IROHA_PEER_LOG=os.path.join(root, "peer.log"), IROHA_PEER_PROCESS_RECORD=os.path.join(root, "peer.process.json"), IROHA_PEER_INDEX="0")
records = [(os.path.join(root, source), os.path.join(root, "fd" + str(fd)), size, fd) for source, size, fd in (("key", 71, 198), ("credential", 257, 200))]
def selection():
    return {"initial_config": os.path.join(root, "initial.toml"), "initial_identity": _taira_file_identity(os.lstat(os.path.join(root, "initial.toml"))),
        "beacon_config": os.path.join(root, "beacon.toml"), "beacon_identity": _taira_file_identity(os.lstat(os.path.join(root, "beacon.toml"))),
        "sources": [{"path": source, "size": size, "descriptor": fd, "identity": _taira_file_identity(os.lstat(source))} for source, _launch, size, fd in records]}
consumer = "import os; exec('for fd,size in ((198,71),(200,257)):\\n assert len(os.read(fd,size+1))==size\\n os.lseek(fd,0,0)\\n assert os.write(fd,bytes(size))==size\\n os.fsync(fd)\\n os.ftruncate(fd,0)\\n os.fsync(fd)')"
signer_consumer = "import os; assert len(os.read(198,72))==71; os.lseek(198,0,0); assert os.write(198,bytes(71))==71; os.fsync(198); os.ftruncate(198,0); os.fsync(198)"
process = launch_taira_process([sys.executable, "-c", signer_consumer], env, records[:1])
assert process.wait(timeout=10) == 0
assert os.lstat(records[0][1]).st_size == 0
try:
    _preflight_taira_runtime_paths(records[:1] + [(records[0][0], os.path.join(root, "fd199"), 32, 199)])
except RuntimeError as error:
    assert "fixed runtime descriptors" in str(error)
else:
    raise AssertionError("retired mint-finality descriptor was accepted")
process = launch_taira_process([sys.executable, "-c", consumer], env, records, selection())
assert process.wait(timeout=10) == 0
assert all(os.lstat(launch).st_size == 0 for _source, launch, _size, _fd in records)
checked = selection()
with open(records[0][0], "r+b") as source:
    source.write(b"B")
try:
    launch_taira_process([sys.executable, "-c", "raise AssertionError('must not start')"], env, records, checked)
except RuntimeError as error:
    assert "identity changed" in str(error)
else:
    raise AssertionError("changed signing source was accepted")
checked = selection()
with open(checked["initial_config"], "ab") as source:
    source.write(b"changed")
try:
    launch_taira_process([sys.executable, "-c", "raise AssertionError('must not start')"], env, records, checked)
except RuntimeError as error:
    assert "configuration identity changed" in str(error)
else:
    raise AssertionError("changed original configuration was accepted")
placeholder = os.open(os.devnull, os.O_RDONLY)
os.dup2(placeholder, 200)
try:
    try:
        launch_taira_process([sys.executable, "-c", "raise AssertionError('must not start')"], env, records, selection())
    except RuntimeError as error:
        assert "occupied" in str(error)
    else:
        raise AssertionError("occupied beacon FD200 was accepted")
    os.fstat(200)
finally:
    os.close(200)
    os.close(placeholder)
"#
        );
        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg(python)
            .arg(root.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(root.path().join("credential")).unwrap(),
            [0x43; 257]
        );
        assert_eq!(
            fs::read(root.path().join("beacon.toml")).unwrap(),
            b"projected exact bytes"
        );
        assert_eq!(
            fs::metadata(root.path().join("credential"))
                .unwrap()
                .nlink(),
            1
        );
    }

    #[test]
    fn private_beacon_launch_arguments_require_explicit_complete_selection() {
        let mut arguments = Vec::new();
        write_taira_launch_arguments(&mut arguments, true).unwrap();
        let parser = format!(
            "set -euo pipefail\nPEER_COUNT=4\nSELECTED_PEERS=all\n{}\nprintf '%s' \"$SELECTED_PEERS|$BEACON_CONFIG|$BEACON_CREDENTIAL|$KAGAMI_BIN\"\n",
            String::from_utf8(arguments).unwrap()
        );
        let invoke = |args: &[&str]| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(&parser)
                .arg("start.sh")
                .args(args)
                .output()
                .unwrap()
        };
        assert_eq!(invoke(&[]).stdout, b"all|||");
        assert_eq!(invoke(&["--peer-index", "0"]).stdout, b"0|||");
        let complete = [
            "--peer-index",
            "2",
            "--beacon-config",
            "/private/run/beacon/seat-1/beacon.toml",
            "--beacon-credential",
            "/private/run/beacon/seat-1/iroha-global-beacon-partial-signer-v1.norito",
            "--kagami-bin",
            "/private/run/bin/kagami",
        ];
        assert!(invoke(&complete).status.success());
        for args in [
            vec!["--peer-index", "4"],
            vec!["--peer-index", "00"],
            vec!["--peer-index", "0", "--peer-index", "1"],
            vec![
                "--peer-index",
                "0",
                "--beacon-config",
                "/private/beacon.toml",
            ],
            vec!["--beacon-config", "/private/beacon.toml"],
            vec!["--beacon-credential", "/private/credential"],
            vec!["--kagami-bin", "/private/bin/kagami"],
            vec!["--runtime-toggle", "true"],
            vec!["--peer-index"],
        ] {
            assert_eq!(invoke(&args).status.code(), Some(2));
        }
        let mut arguments = Vec::new();
        write_taira_launch_arguments(&mut arguments, false).unwrap();
        let stop = format!(
            "set -euo pipefail\nPEER_COUNT=4\nSELECTED_PEERS=all\n{}",
            String::from_utf8(arguments).unwrap()
        );
        assert!(
            std::process::Command::new("bash")
                .arg("-c")
                .arg(&stop)
                .arg("stop.sh")
                .args([
                    "--peer-index",
                    "2",
                    "--beacon-config",
                    "/private/run/beacon/seat-1/beacon.toml"
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            !std::process::Command::new("bash")
                .arg("-c")
                .arg(&stop)
                .arg("stop.sh")
                .args([
                    "--peer-index",
                    "2",
                    "--beacon-credential",
                    "/private/credential"
                ])
                .status()
                .unwrap()
                .success()
        );
    }
}
fn resolve_localnet_da_proof_policies(config: &actual::Root) -> DaProofPolicyBundle {
    iroha_core::da::proof_policy_bundle(&config.nexus.lane_config)
}
/// Generate a fresh genesis key or explicitly seeded development key pair.
pub fn generate_genesis_key_pair(
    base_seed: Option<&[u8]>,
    extra_seed: &[u8],
) -> Result<(iroha_crypto::PublicKey, ExposedPrivateKey)> {
    let key_pair = match base_seed {
        Some(base_seed) => iroha_crypto::KeyPair::try_from_seed(
            base_seed
                .iter()
                .chain(extra_seed)
                .copied()
                .collect::<Vec<_>>(),
            iroha_crypto::Algorithm::default(),
        )?,
        #[cfg(test)]
        None => KeyPair::from(REAL_GENESIS_ACCOUNT_KEYPAIR.private_key().clone()),
        #[cfg(not(test))]
        None => {
            iroha_crypto::KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::default())?
        }
    };
    let (public_key, private_key) = key_pair.into_parts();
    Ok((public_key, ExposedPrivateKey(private_key)))
}
fn generate_account_key_pair(
    base_seed: Option<&[u8]>,
    extra_seed: &[u8],
) -> Result<(iroha_crypto::PublicKey, ExposedPrivateKey)> {
    let key_pair = match base_seed {
        Some(seed) => iroha_crypto::KeyPair::try_from_seed(
            seed.iter().chain(extra_seed).copied().collect::<Vec<_>>(),
            iroha_crypto::Algorithm::default(),
        )?,
        None => {
            iroha_crypto::KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::default())?
        }
    };
    let (public_key, private_key) = key_pair.into_parts();
    Ok((public_key, ExposedPrivateKey(private_key)))
}
fn generate_bls_key_pair(
    base_seed: Option<&[u8]>,
    extra_seed: &[u8],
) -> Result<(iroha_crypto::PublicKey, ExposedPrivateKey, Vec<u8>)> {
    let kp = match base_seed {
        Some(seed) => {
            let material = seed.iter().chain(extra_seed).copied().collect::<Vec<_>>();
            iroha_crypto::KeyPair::try_from_seed(material, iroha_crypto::Algorithm::BlsNormal)?
        }
        None => {
            iroha_crypto::KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::BlsNormal)?
        }
    };
    let pop = iroha_crypto::bls_normal_pop_prove(kp.private_key())?;
    let (public_key, private_key) = kp.into_parts();
    Ok((public_key, ExposedPrivateKey(private_key), pop))
}
fn require_taira_private_output_outside_git(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    for ancestor in absolute.ancestors() {
        match fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => {
                return Err(eyre!(
                    "Taira private runtime output must be outside a Git checkout"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).wrap_err("inspect private runtime output ancestry"),
        }
    }
    Ok(())
}

fn generate_soranet_transport_key_pair(
    base_seed: Option<&[u8]>,
    peer_index: &[u8],
) -> Result<(iroha_crypto::PublicKey, ExposedPrivateKey)> {
    generate_peer_ed25519_key_pair(base_seed, SORANET_TRANSPORT_SEED_DOMAIN, peer_index)
}
fn generate_streaming_identity_key_pair(
    base_seed: Option<&[u8]>,
    peer_index: &[u8],
) -> Result<(iroha_crypto::PublicKey, ExposedPrivateKey)> {
    generate_peer_ed25519_key_pair(base_seed, STREAMING_IDENTITY_SEED_DOMAIN, peer_index)
}
fn generate_peer_ed25519_key_pair(
    base_seed: Option<&[u8]>,
    seed_domain: &[u8],
    peer_index: &[u8],
) -> Result<(iroha_crypto::PublicKey, ExposedPrivateKey)> {
    let key_pair = match base_seed {
        Some(seed) => KeyPair::try_from_seed(
            seed.iter()
                .chain(seed_domain)
                .chain(peer_index)
                .copied()
                .collect::<Vec<_>>(),
            iroha_crypto::Algorithm::Ed25519,
        )?,
        None => KeyPair::try_random_with_algorithm(iroha_crypto::Algorithm::Ed25519)?,
    };
    let (public_key, private_key) = key_pair.into_parts();
    Ok((public_key, ExposedPrivateKey(private_key)))
}
fn repo_root_path() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            Path::to_path_buf,
        );
    root.canonicalize().unwrap_or(root)
}
fn resolve_target_dir(repo_root: &Path, target_dir: Option<&str>) -> PathBuf {
    target_dir.map_or_else(
        || repo_root.join("target"),
        |path| {
            let target_dir = PathBuf::from(path);
            if target_dir.is_absolute() {
                target_dir
            } else {
                repo_root.join(target_dir)
            }
        },
    )
}
fn default_irohad_bin_paths(taira: bool) -> (PathBuf, PathBuf) {
    let repo_root = repo_root_path();
    let target_dir = resolve_target_dir(&repo_root, env::var("CARGO_TARGET_DIR").ok().as_deref());
    let binary = if taira { "iroha3d_taira" } else { "iroha3d" };
    (
        target_dir.join("debug").join(binary),
        target_dir.join("release").join(binary),
    )
}

fn write_taira_pidfd_preflight(output: &mut impl Write) -> Result<()> {
    writeln!(
        output,
        "command -v python3 >/dev/null 2>&1 || {{ echo \"python3 is required for Taira pidfd process control\" >&2; exit 1; }}"
    )?;
    output.write_all(
        br#"python3 - <<'PY'
import os
import platform
import select
import signal
import sys

if platform.system() != "Linux":
    raise SystemExit("Taira process control requires Linux pidfds and procfs")
if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit("Taira process control requires pidfd_open and pidfd_send_signal")
if not hasattr(os, "O_CLOEXEC") or not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("Taira process control requires safe Linux procfs open flags")
if not hasattr(select, "poll"):
    raise SystemExit("Taira process control requires pollable pidfds")
for required in ("/proc", "/proc/self/stat", "/proc/self/status", "/proc/sys/kernel/random/boot_id"):
    if not os.path.exists(required):
        raise SystemExit("Taira process control requires Linux procfs")
try:
    descriptor = os.pidfd_open(os.getpid(), 0)
    try:
        signal.pidfd_send_signal(descriptor, 0, None, 0)
        poller = select.poll()
        poller.register(descriptor, select.POLLIN | select.POLLHUP)
        poller.poll(0)
    finally:
        os.close(descriptor)
except OSError as error:
    raise SystemExit("Taira process control cannot exercise native Linux pidfds: {}".format(error))
PY
for legacy_pidfile in "$DIR"/peer*.pid; do
  if [ -e "$legacy_pidfile" ] || [ -L "$legacy_pidfile" ]; then
    echo "retired Taira PID file is unsupported: $legacy_pidfile" >&2
    exit 1
  fi
done
"#,
    )?;
    Ok(())
}

const TAIRA_RUNTIME_LAUNCH_PY: &str = r#"
def _taira_file_identity(metadata):
    return tuple(getattr(metadata, field) for field in (
        "st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))

def _require_taira_fd_vacant(descriptor):
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise
    raise RuntimeError("refusing occupied Taira runtime descriptor {}".format(descriptor))

def _reserve_taira_fds(reserved):
    for descriptor in (198, 200):
        _require_taira_fd_vacant(descriptor)
    placeholder = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    if placeholder in (198, 200):
        reserved.add(placeholder)
    try:
        for descriptor in (198, 200):
            if descriptor not in reserved:
                _require_taira_fd_vacant(descriptor)
                os.dup2(placeholder, descriptor, inheritable=False)
                reserved.add(descriptor)
    finally:
        if placeholder not in reserved:
            os.close(placeholder)

def _preflight_taira_runtime_paths(records, expected_identities=None):
    descriptors = tuple(record[3] for record in records)
    if descriptors not in ((198,), (198, 200)):
        raise RuntimeError("Taira requires exactly the fixed runtime descriptors")
    if 200 in descriptors and expected_identities is None:
        raise RuntimeError("Taira beacon descriptor requires native validation")
    if expected_identities is not None and set(expected_identities) != set(descriptors):
        raise RuntimeError("native Taira descriptor selection does not match the handoff")
    paths = [path for source, launch, _size, _descriptor in records for path in (source, launch)]
    if len(set(os.path.realpath(path) for path in paths)) != len(paths):
        raise RuntimeError("Taira retained sources and launch paths must be distinct")
    identities = set()
    retained = []
    stale = []
    try:
        for source, launch, size, descriptor in records:
            if ((descriptor, size) != (198, 71)
                    and not (descriptor == 200 and type(size) is int and 0 < size <= 16 * 1024 * 1024)):
                raise RuntimeError("Taira private record length does not match its fixed descriptor")
            source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            retained.append((source_fd, None, launch, size, descriptor))
            before = os.fstat(source_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size != size):
                raise RuntimeError("untrusted persistent Taira runtime signer file")
            retained[-1] = (source_fd, before, launch, size, descriptor)
            if (_taira_file_identity(os.lstat(source)) != _taira_file_identity(before)
                    or (expected_identities is not None
                        and _taira_file_identity(before) != tuple(expected_identities[descriptor]))):
                raise RuntimeError("Taira source path or native descriptor identity changed")
            identity = (before.st_dev, before.st_ino)
            if identity in identities:
                raise RuntimeError("Taira private paths alias one inode")
            identities.add(identity)
            try:
                previous = os.lstat(launch)
            except FileNotFoundError:
                previous = None
            if previous is not None:
                if (not stat.S_ISREG(previous.st_mode) or previous.st_uid != os.geteuid()
                        or stat.S_IMODE(previous.st_mode) != 0o600 or previous.st_nlink != 1
                        or previous.st_size not in (0, size)):
                    raise RuntimeError("untrusted stale Taira runtime launch file")
                identity = (previous.st_dev, previous.st_ino)
                if identity in identities:
                    raise RuntimeError("Taira private paths alias one inode")
                identities.add(identity)
                stale.append((launch, previous))
        for launch, previous in stale:
            if _taira_file_identity(os.lstat(launch)) != _taira_file_identity(previous):
                raise RuntimeError("Taira stale launch file changed before replacement")
        return retained, stale
    except BaseException:
        for source_fd, _before, _launch, _size, _descriptor in retained:
            os.close(source_fd)
        raise

def _stage_taira_runtime_record(record, owned, source_path=None):
    source_fd, before, launch, size, descriptor = record
    launch_fd = os.open(launch, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        created = os.fstat(launch_fd)
    except BaseException:
        os.close(launch_fd)
        raise
    owned.append((launch_fd, launch, created.st_dev, created.st_ino, size))
    secret = bytearray(size)
    view = memoryview(secret)
    try:
        offset = 0
        while offset < size:
            count = os.readv(source_fd, [view[offset:]])
            if count <= 0:
                raise RuntimeError("short Taira runtime signer source")
            offset += count
        if (_taira_file_identity(os.fstat(source_fd)) != _taira_file_identity(before)
                or (source_path is not None
                    and _taira_file_identity(os.lstat(source_path)) != _taira_file_identity(before))):
            raise RuntimeError("Taira runtime signer source changed while staging")
        offset = 0
        while offset < size:
            count = os.write(launch_fd, view[offset:])
            if count <= 0:
                raise RuntimeError("short Taira runtime launch write")
            offset += count
        os.fsync(launch_fd)
        os.lseek(launch_fd, 0, os.SEEK_SET)
        ready = os.fstat(launch_fd)
        if (not stat.S_ISREG(ready.st_mode) or ready.st_uid != os.geteuid()
                or stat.S_IMODE(ready.st_mode) != 0o600 or ready.st_nlink != 1 or ready.st_size != size
                or (ready.st_dev, ready.st_ino) != (created.st_dev, created.st_ino)):
            raise RuntimeError("untrusted Taira runtime launch file")
        os.dup2(launch_fd, descriptor, inheritable=True)
    finally:
        for index in range(size):
            secret[index] = 0
        view.release()

def _erase_owned_taira_launch(record):
    descriptor, path, device, inode, size = record
    failures = []
    try:
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) != (device, inode):
            raise RuntimeError("owned Taira launch descriptor identity changed")
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            zeros = bytes(size)
            offset = 0
            while offset < size:
                count = os.write(descriptor, zeros[offset:])
                if count <= 0:
                    raise RuntimeError("short Taira launch erasure")
                offset += count
            os.fsync(descriptor)
        except BaseException as error:
            failures.append(error)
        try:
            os.ftruncate(descriptor, 0)
            os.fsync(descriptor)
        except BaseException as error:
            failures.append(error)
        try:
            named = os.lstat(path)
        except FileNotFoundError:
            named = None
        if named is not None and stat.S_ISREG(named.st_mode) and (named.st_dev, named.st_ino) == (device, inode):
            os.unlink(path)
    finally:
        os.close(descriptor)
    if failures:
        raise RuntimeError("Taira owned launch erasure encountered an I/O failure") from failures[0]

def _check_taira_selection_files(selection):
    for path_field, identity_field in (("initial_config", "initial_identity"), ("beacon_config", "beacon_identity")):
        if _taira_file_identity(os.lstat(selection[path_field])) != tuple(selection[identity_field]):
            raise RuntimeError("native Taira configuration identity changed before launch")

def launch_taira_process(cmd, env, records, selection=None):
    reserved, retained, owned = set(), [], []
    started = False
    process = None
    try:
        _reserve_taira_fds(reserved)
        expected_identities = None
        if selection is not None:
            _check_taira_selection_files(selection)
            expected_identities = {source["descriptor"]: source["identity"] for source in selection["sources"]}
            if [(source["path"], source["size"], source["descriptor"]) for source in selection["sources"]] != [
                    (source, size, descriptor) for source, _launch, size, descriptor in records]:
                raise RuntimeError("native Taira source selection does not match launch paths")
        retained, stale = _preflight_taira_runtime_paths(records, expected_identities)
        for launch, previous in stale:
            if _taira_file_identity(os.lstat(launch)) != _taira_file_identity(previous):
                raise RuntimeError("Taira stale launch file changed before replacement")
            os.unlink(launch)
        for record, source in zip(retained, records):
            _stage_taira_runtime_record(record, owned, source[0])
        if selection is not None:
            _check_taira_selection_files(selection)
        pass_fds = (198,) if selection is None else (198, 200)
        with open(env["IROHA_PEER_LOG"], "ab", buffering=0) as log:
            process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env,
                close_fds=True, pass_fds=pass_fds, start_new_session=True)
        capture_taira_start(process.pid, env["IROHA_PEER_PROCESS_RECORD"], int(env["IROHA_PEER_INDEX"]), cmd)
        started = True
        return process
    finally:
        failures = []
        child_reaped = process is None
        if process is not None and not started:
            try:
                # This unreaped Popen child remains ours even if identity capture failed.
                # Reap it before erasing the launch records or returning a failed start.
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5.0)
                else:
                    process.wait(timeout=0)
                child_reaped = True
            except BaseException as error:
                failures.append(error)
        for descriptor in reserved:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(error)
        for descriptor, _before, _launch, _size, _target in retained:
            try:
                os.close(descriptor)
            except BaseException as error:
                failures.append(error)
        for record in owned:
            try:
                if started or not child_reaped:
                    os.close(record[0])
                else:
                    _erase_owned_taira_launch(record)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise RuntimeError("Taira runtime descriptor cleanup failed") from failures[0]
"#;

const TAIRA_PROCESS_IDENTITY_PY: &str = r#"
import errno
import json
import re
import select
import signal
import time

_PROCESS_KEYS = {
    "schema_version", "peer_index", "pid", "boot_id", "start_time_ticks",
    "executable_path", "executable_device", "executable_inode", "argv",
    "uid", "gid", "session_id", "process_group_id",
}
_RUNTIME_KEYS = _PROCESS_KEYS - {"schema_version", "peer_index"}
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

def _proc_read(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        payload = bytearray()
        while len(payload) <= limit:
            chunk = os.read(descriptor, min(16384, limit + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        os.close(descriptor)
    if len(payload) > limit:
        raise RuntimeError("Linux procfs record exceeds its Taira safety bound: " + path)
    return bytes(payload)

def _parse_stat(payload, pid):
    try:
        fields = payload.decode("ascii").rstrip("\n").rsplit(") ", 1)[1].split()
        result = (fields[0], int(fields[2]), int(fields[3]), int(fields[19]))
    except (IndexError, UnicodeDecodeError, ValueError):
        raise RuntimeError("malformed Linux procfs stat for Taira process {}".format(pid))
    if len(result[0]) != 1 or result[3] <= 0:
        raise RuntimeError("malformed Linux procfs stat for Taira process {}".format(pid))
    return result

def _status_ids(payload, pid):
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        raise RuntimeError("malformed Linux procfs status for Taira process {}".format(pid))
    result = []
    for label in ("Uid:", "Gid:"):
        rows = [line for line in text.splitlines() if line.startswith(label)]
        if len(rows) != 1:
            raise RuntimeError("malformed Linux procfs status for Taira process {}".format(pid))
        try:
            values = tuple(int(value) for value in rows[0][len(label):].split())
        except ValueError:
            raise RuntimeError("malformed Linux procfs status for Taira process {}".format(pid))
        if len(values) != 4:
            raise RuntimeError("malformed Linux procfs status for Taira process {}".format(pid))
        result.append(values[1])
    return tuple(result)

def _open_pidfd(pid):
    try:
        return os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return None
    except OSError as error:
        if error.errno == errno.ESRCH:
            return None
        raise RuntimeError("cannot open pidfd for Taira process {}: {}".format(pid, error))

def _pidfd_signal(descriptor, signal_number):
    try:
        signal.pidfd_send_signal(descriptor, signal_number, None, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError as error:
        if error.errno == errno.ESRCH:
            return False
        raise RuntimeError("cannot signal exact Taira process through pidfd: {}".format(error))

def _pidfd_wait(descriptor, timeout_seconds):
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP)
    return bool(poller.poll(min(int(timeout_seconds * 1000), 2147483647)))

def _observe(pid):
    root = "/proc/{}".format(pid)
    try:
        before = _parse_stat(_proc_read(root + "/stat", 16384), pid)
        if before[0] == "Z":
            return None
        cmdline = _proc_read(root + "/cmdline", 65536)
        if not cmdline or not cmdline.endswith(b"\0"):
            return None
        raw_argv = cmdline[:-1].split(b"\0")
        if not raw_argv or any(not argument for argument in raw_argv):
            return None
        argv = [os.fsdecode(argument) for argument in raw_argv]
        executable_path = os.readlink(root + "/exe")
        executable = os.stat(root + "/exe")
        uid, gid = _status_ids(_proc_read(root + "/status", 131072), pid)
        after = _parse_stat(_proc_read(root + "/stat", 16384), pid)
        cmdline_after = _proc_read(root + "/cmdline", 65536)
        executable_path_after = os.readlink(root + "/exe")
        executable_after = os.stat(root + "/exe")
        uid_after, gid_after = _status_ids(_proc_read(root + "/status", 131072), pid)
        if (after != before or cmdline_after != cmdline or executable_path_after != executable_path
                or (executable_after.st_dev, executable_after.st_ino) != (executable.st_dev, executable.st_ino)
                or (uid_after, gid_after) != (uid, gid)):
            raise RuntimeError("Taira process changed while observing procfs")
        boot_id = _proc_read("/proc/sys/kernel/random/boot_id", 128).decode("ascii").strip()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except UnicodeDecodeError:
        raise RuntimeError("malformed Linux boot identity for Taira process {}".format(pid))
    return {
        "pid": pid,
        "boot_id": boot_id,
        "start_time_ticks": before[3],
        "executable_path": executable_path,
        "executable_device": executable.st_dev,
        "executable_inode": executable.st_ino,
        "argv": argv,
        "uid": uid,
        "gid": gid,
        "session_id": before[2],
        "process_group_id": before[1],
    }

def _bound_observation(descriptor, pid):
    if not _pidfd_signal(descriptor, 0):
        return None
    observed = _observe(pid)
    if not _pidfd_signal(descriptor, 0):
        return None
    return observed

def _runtime_identity(record):
    return {key: record[key] for key in _RUNTIME_KEYS}

def _validate_record(record, peer_index, config_path, executable_path=None):
    if type(record) is not dict or set(record) != _PROCESS_KEYS:
        raise RuntimeError("Taira process record violates the exact V1 schema")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise RuntimeError("Taira process record has the wrong schema version")
    if type(record["peer_index"]) is not int or record["peer_index"] != peer_index:
        raise RuntimeError("Taira process record has the wrong peer index")
    integer_fields = (
        "pid", "start_time_ticks", "executable_device", "executable_inode",
        "uid", "gid", "session_id", "process_group_id",
    )
    if any(type(record[field]) is not int for field in integer_fields):
        raise RuntimeError("Taira process record contains a non-integer identity field")
    pid = record["pid"]
    if not (1 < pid <= 2147483647 and 0 < record["start_time_ticks"] <= 18446744073709551615
            and 0 <= record["executable_device"] <= 18446744073709551615
            and 0 < record["executable_inode"] <= 18446744073709551615
            and 0 <= record["uid"] <= 4294967295 and 0 <= record["gid"] <= 4294967295
            and record["session_id"] == pid and record["process_group_id"] == pid):
        raise RuntimeError("Taira process record contains a malformed identity")
    if type(record["boot_id"]) is not str or _BOOT_ID.fullmatch(record["boot_id"]) is None:
        raise RuntimeError("Taira process record contains a malformed Linux boot identity")
    executable = record["executable_path"]
    if (type(executable) is not str or not os.path.isabs(executable)
            or os.path.normpath(executable) != executable
            or os.path.basename(executable) != "iroha3d_taira" or "\0" in executable):
        raise RuntimeError("Taira process record contains a malformed executable path")
    if executable_path is not None and executable != executable_path:
        raise RuntimeError("Taira process record names a substituted executable")
    argv = record["argv"]
    if type(argv) is not list or argv[:4] != [executable, "--sora", "--config", config_path]:
        raise RuntimeError("Taira process record does not bind the exact daemon argv/config")
    tail = argv[4:]
    if tail[:1] == ["--config-blake3"]:
        if len(tail) < 2 or type(tail[1]) is not str or re.fullmatch("[0-9a-f]{64}", tail[1]) is None:
            raise RuntimeError("Taira process record contains an invalid native configuration digest")
        tail = tail[2:]
    if tail not in ([], ["--sumeragi-assert-fresh-key"]):
        raise RuntimeError("Taira process record does not bind the exact daemon argv/config")
    return record

def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError("duplicate Taira process record key: " + key)
        result[key] = value
    return result

def _read_record(path, peer_index, config_path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size <= 0 or before.st_size > 4096):
            raise RuntimeError("Taira process record lacks exact owner-only custody")
        payload = bytearray()
        while len(payload) <= 4096:
            chunk = os.read(descriptor, min(4097 - len(payload), 4096))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise RuntimeError("Taira process record changed while reading")
    finally:
        os.close(descriptor)
    if len(payload) > 4096:
        raise RuntimeError("Taira process record exceeds its safety bound")
    try:
        record = json.loads(bytes(payload).decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError("Taira process record is not JSON: {}".format(error))
    canonical = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if canonical != bytes(payload):
        raise RuntimeError("Taira process record is not canonical JSON")
    return _validate_record(record, peer_index, config_path), before

def _atomic_publish_record(path, record):
    payload = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > 4096 or os.path.lexists(path):
        raise RuntimeError("refusing to replace an existing Taira process record")
    temporary = os.path.join(os.path.dirname(path), ".peer{}.process.json.{}.tmp".format(record["peer_index"], record["pid"]))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    linked = False
    try:
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise RuntimeError("short Taira process-record write")
            offset += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
                or metadata.st_size != len(payload)):
            raise RuntimeError("new Taira process record lacks owner-only custody")
        os.link(temporary, path, follow_symlinks=False)
        linked = True
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    if not linked:
        raise RuntimeError("Taira process record was not published")
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

def _unlink_record(path, expected):
    current = os.lstat(path)
    stable = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (any(getattr(current, field) != getattr(expected, field) for field in stable)
            or not stat.S_ISREG(current.st_mode) or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) != 0o600 or current.st_nlink != 1):
        raise RuntimeError("Taira process record changed before removal")
    os.unlink(path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

def _terminate_pidfd(descriptor):
    if not _pidfd_signal(descriptor, signal.SIGTERM):
        return
    if _pidfd_wait(descriptor, 10.0):
        return
    if not _pidfd_signal(descriptor, signal.SIGKILL):
        return
    if not _pidfd_wait(descriptor, 5.0):
        raise RuntimeError("exact Taira process did not exit after pidfd SIGKILL")

def preflight_taira_start(record_path, peer_index, expected_argv):
    config_path = expected_argv[3]
    if os.path.lexists(record_path):
        record, _metadata = _read_record(record_path, peer_index, config_path)
        descriptor = _open_pidfd(record["pid"])
        if descriptor is None:
            raise RuntimeError("stale Taira process record must be cleared by stop.sh")
        try:
            observed = _bound_observation(descriptor, record["pid"])
            if observed is None or (observed["boot_id"], observed["start_time_ticks"]) != (record["boot_id"], record["start_time_ticks"]):
                raise RuntimeError("stale or PID-reused Taira process record must be cleared by stop.sh")
            if observed != _runtime_identity(record):
                raise RuntimeError("live Taira process drifted from its persisted identity")
            raise RuntimeError("Taira peer is already running with its exact process identity")
        finally:
            os.close(descriptor)
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) <= 1:
            continue
        pid = int(name)
        descriptor = _open_pidfd(pid)
        if descriptor is None:
            continue
        try:
            observed = _bound_observation(descriptor, pid)
            argv = None if observed is None else observed["argv"]
            if (type(argv) is list and len(argv) >= 4
                    and os.path.basename(argv[0]) == "iroha3d_taira"
                    and argv[1:4] == ["--sora", "--config", config_path]):
                raise RuntimeError("unrecorded Taira process already owns the exact peer config")
        finally:
            os.close(descriptor)

def capture_taira_start(pid, record_path, peer_index, expected_argv):
    descriptor = _open_pidfd(pid)
    if descriptor is None:
        raise RuntimeError("new Taira process exited before pidfd capture")
    try:
        deadline = time.monotonic() + 5.0
        while True:
            observed = _bound_observation(descriptor, pid)
            if observed is None:
                raise RuntimeError("new Taira process exited before identity capture")
            ready = (
                observed["executable_path"] == expected_argv[0]
                and observed["argv"] == expected_argv
                and observed["uid"] == os.geteuid()
                and observed["gid"] == os.getegid()
                and observed["session_id"] == pid
                and observed["process_group_id"] == pid
                and _BOOT_ID.fullmatch(observed["boot_id"]) is not None
            )
            if ready:
                break
            if time.monotonic() >= deadline or _pidfd_wait(descriptor, 0.01):
                raise RuntimeError("new Taira process never reached its exact executable/argv identity")
        record = {"schema_version": 1, "peer_index": peer_index, **observed}
        _validate_record(record, peer_index, expected_argv[3], expected_argv[0])
        _atomic_publish_record(record_path, record)
    except BaseException:
        _terminate_pidfd(descriptor)
        raise
    finally:
        os.close(descriptor)

def stop_taira_process(record_path, peer_index, config_path):
    record, metadata = _read_record(record_path, peer_index, config_path)
    descriptor = _open_pidfd(record["pid"])
    if descriptor is None:
        _unlink_record(record_path, metadata)
        return
    try:
        observed = _bound_observation(descriptor, record["pid"])
        if observed is None or (observed["boot_id"], observed["start_time_ticks"]) != (record["boot_id"], record["start_time_ticks"]):
            _unlink_record(record_path, metadata)
            return
        if observed != _runtime_identity(record):
            raise RuntimeError("refusing to signal a Taira process whose identity drifted")
        _terminate_pidfd(descriptor)
        if not _pidfd_wait(descriptor, 0.0):
            raise RuntimeError("exact Taira process remains live after pidfd termination")
        _unlink_record(record_path, metadata)
    finally:
        os.close(descriptor)
"#;

const TAIRA_BEACON_SELECTION_PY: &str = r#"
def select_taira_beacon_launch(env, config_path, credential_path, kagami):
    if not os.path.isabs(kagami) or os.path.realpath(kagami) != kagami or not os.access(kagami, os.X_OK):
        raise RuntimeError("beacon launch requires the explicit native Kagami executable")
    native = subprocess.Popen([kagami, "localnet", "validate-beacon-launch",
        "--network-dir", env["IROHA_NETWORK_DIR"], "--peer-index", env["IROHA_PEER_INDEX"],
        "--beacon-config", config_path, "--beacon-credential", credential_path],
        stdout=subprocess.PIPE, close_fds=True)
    try:
        deadline = time.monotonic() + 60.0
        payload = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([native.stdout], [], [], remaining)[0]:
                raise RuntimeError("native Taira launch selection exceeded its deadline")
            chunk = os.read(native.stdout.fileno(), 16385 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > 16384:
                raise RuntimeError("native Taira launch selection exceeds its bound")
        if native.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise RuntimeError("native Taira beacon launch validation failed")
    finally:
        native.stdout.close()
        if native.poll() is None:
            native.terminate()
            try:
                native.wait(timeout=5)
            except subprocess.TimeoutExpired:
                native.kill()
                native.wait(timeout=5)
    selection = json.loads(payload, object_pairs_hook=_no_duplicates)
    if (type(selection) is not dict or set(selection) != {
            "schema", "peer_index", "initial_config", "initial_identity", "beacon_config",
            "beacon_identity", "config_blake3", "sources"}
            or selection["schema"] != "iroha.taira.private-beacon-launch.v1"
            or type(selection["peer_index"]) is not int
            or selection["peer_index"] != int(env["IROHA_PEER_INDEX"])
            or selection["initial_config"] != os.path.join(env["IROHA_NETWORK_DIR"], "peer{}.toml".format(env["IROHA_PEER_INDEX"]))
            or selection["beacon_config"] != config_path
            or type(selection["config_blake3"]) is not str
            or re.fullmatch("[0-9a-f]{64}", selection["config_blake3"]) is None):
        raise RuntimeError("native Taira launch selection violates its exact public schema")
    sources = selection["sources"]
    if type(sources) is not list or len(sources) != 2:
        raise RuntimeError("native Taira launch selection omits fixed descriptors")
    for source, descriptor in zip(sources, (198, 200)):
        if (type(source) is not dict or set(source) != {"descriptor", "path", "size", "identity"}
                or type(source["descriptor"]) is not int or source["descriptor"] != descriptor
                or type(source["path"]) is not str or not os.path.isabs(source["path"])
                or type(source["size"]) is not int or source["size"] <= 0):
            raise RuntimeError("native Taira launch selection has an invalid descriptor record")
    for identity in [selection["initial_identity"], selection["beacon_identity"]] + [source["identity"] for source in sources]:
        if type(identity) is not list or len(identity) != 9 or any(type(field) is not int for field in identity):
            raise RuntimeError("native Taira launch selection has an invalid file identity")
    if sources[1]["path"] != credential_path:
        raise RuntimeError("native Taira launch selection changed the beacon credential path")
    return selection
"#;

fn write_taira_launch_arguments(writer: &mut impl Write, start: bool) -> Result<()> {
    writer.write_all(br#"BEACON_CONFIG=""
BEACON_CREDENTIAL=""
KAGAMI_BIN=""
peer_index=""
while [ "$#" -gt 0 ]; do
  if [ "$#" -lt 2 ]; then echo "missing launch argument value" >&2; exit 2; fi
  case "$1" in
    --peer-index)
      if [ -n "$peer_index" ] || [[ ! $2 =~ ^(0|[1-9][0-9]{0,4})$ ]]; then echo "invalid or repeated peer index" >&2; exit 2; fi
      peer_index=$((10#$2))
      if (( peer_index >= PEER_COUNT )); then echo "peer index out of range" >&2; exit 2; fi
      SELECTED_PEERS="$peer_index"
      ;;
    --beacon-config)
      if [ -n "$BEACON_CONFIG" ] || [[ $2 != /* ]]; then echo "invalid or repeated beacon config" >&2; exit 2; fi
      BEACON_CONFIG="$2"
      ;;
"#)?;
    if start {
        writer.write_all(br#"    --beacon-credential)
      if [ -n "$BEACON_CREDENTIAL" ] || [[ $2 != /* ]]; then echo "invalid or repeated beacon credential" >&2; exit 2; fi
      BEACON_CREDENTIAL="$2"
      ;;
    --kagami-bin)
      if [ -n "$KAGAMI_BIN" ] || [[ $2 != /* ]]; then echo "invalid or repeated native Kagami path" >&2; exit 2; fi
      KAGAMI_BIN="$2"
      ;;
"#)?;
    }
    writer.write_all(
        br#"    *) echo "unknown private launch argument: $1" >&2; exit 2 ;;
  esac
  shift 2
done
if [ -n "$BEACON_CONFIG" ] && [ -z "$peer_index" ]; then
  echo "beacon selection requires an explicit peer index" >&2; exit 2
fi
"#,
    )?;
    if start {
        writer.write_all(
            br#"if [ -n "$BEACON_CONFIG" ]; then
  if [ -z "$BEACON_CREDENTIAL" ] || [ -z "$KAGAMI_BIN" ]; then
    echo "beacon selection requires --beacon-credential and --kagami-bin" >&2; exit 2
  fi
elif [ -n "$BEACON_CREDENTIAL" ] || [ -n "$KAGAMI_BIN" ]; then
  echo "beacon credential and native Kagami require --beacon-config" >&2; exit 2
fi
"#,
        )?;
    }
    Ok(())
}

fn write_scripts(
    out_dir: &Path,
    peers: u16,
    sora_profile_enabled: bool,
    taira: bool,
    client_account_literal: &str,
    fee_asset_definition_id: &str,
) -> Result<()> {
    let start = out_dir.join("start.sh");
    let stop = out_dir.join("stop.sh");
    write_start_script(
        &start,
        peers,
        sora_profile_enabled,
        taira,
        client_account_literal,
        fee_asset_definition_id,
    )?;
    write_stop_script(&stop, peers, taira)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&start, PermissionsExt::from_mode(0o700))
            .wrap_err_with(|| format!("failed to mark {} executable", start.display()))?;
        fs::set_permissions(&stop, PermissionsExt::from_mode(0o700))
            .wrap_err_with(|| format!("failed to mark {} executable", stop.display()))?;
    }
    Ok(())
}
#[allow(clippy::similar_names, clippy::too_many_lines)]
fn write_start_script(
    start: &Path,
    peers: u16,
    sora_profile_enabled: bool,
    taira: bool,
    client_account_literal: &str,
    fee_asset_definition_id: &str,
) -> Result<()> {
    let (default_irohad_debug, default_irohad_release) = default_irohad_bin_paths(taira);
    let default_iroha_debug = default_irohad_debug.with_file_name("iroha");
    let default_iroha_release = default_irohad_release.with_file_name("iroha");
    let default_irohad_debug = crate::shell::quote_path(&default_irohad_debug)?;
    let default_irohad_release = crate::shell::quote_path(&default_irohad_release)?;
    let default_iroha_debug = crate::shell::quote_path(&default_iroha_debug)?;
    let default_iroha_release = crate::shell::quote_path(&default_iroha_release)?;
    let client_account_literal = crate::shell::single_quote(client_account_literal)?;
    let fee_asset_definition_id = crate::shell::single_quote(fee_asset_definition_id)?;
    let mut start_file = BufWriter::new(custody::create_file(start)?);
    let sora_mode_env = if sora_profile_enabled { "1" } else { "0" };
    let taira_mode_env = if taira { "1" } else { "0" };
    writeln!(start_file, "#!/usr/bin/env bash")?;
    writeln!(start_file, "set -euo pipefail")?;
    writeln!(start_file, "umask 077")?;
    writeln!(start_file, "DIR=$(cd \"$(dirname \"$0\")\" && pwd)")?;
    writeln!(start_file, "cd \"$DIR\"")?;
    writeln!(start_file, "PEER_COUNT={peers}")?;
    writeln!(
        start_file,
        "SELECTED_PEERS=\"$(seq 0 \"$((PEER_COUNT - 1))\")\""
    )?;
    if taira {
        write_taira_launch_arguments(&mut start_file, true)?;
    } else {
        writeln!(
            start_file,
            "BEACON_CONFIG=\"\"; BEACON_CREDENTIAL=\"\"; KAGAMI_BIN=\"\""
        )?;
        writeln!(start_file, "if [ \"$#\" -ne 0 ]; then")?;
        writeln!(
            start_file,
            "  if [ \"$#\" -ne 2 ] || [ \"$1\" != \"--peer-index\" ]; then"
        )?;
        writeln!(
            start_file,
            "    echo \"usage: $0 [--peer-index INDEX]\" >&2"
        )?;
        writeln!(start_file, "    exit 2")?;
        writeln!(start_file, "  fi")?;
        writeln!(
            start_file,
            "  if [[ ! $2 =~ ^(0|[1-9][0-9]{{0,4}})$ ]]; then"
        )?;
        writeln!(start_file, "    echo \"invalid peer index: $2\" >&2")?;
        writeln!(start_file, "    exit 2")?;
        writeln!(start_file, "  fi")?;
        writeln!(start_file, "  peer_index=$((10#$2))")?;
        writeln!(start_file, "  if (( peer_index >= PEER_COUNT )); then")?;
        writeln!(start_file, "    echo \"invalid peer index: $2\" >&2")?;
        writeln!(start_file, "    exit 2")?;
        writeln!(start_file, "  fi")?;
        writeln!(start_file, "  SELECTED_PEERS=\"$peer_index\"")?;
        writeln!(start_file, "fi")?;
    }
    if !taira {
        writeln!(start_file, "pid_is_running() {{")?;
        writeln!(start_file, "  pid=\"$1\"")?;
        writeln!(
            start_file,
            "  case \"$pid\" in ''|*[!0-9]*) return 1 ;; esac"
        )?;
        writeln!(start_file, "  command -v ps >/dev/null 2>&1 || return 0")?;
        writeln!(start_file, "  ps -p \"$pid\" -o pid= >/dev/null 2>&1")?;
        writeln!(start_file, "}}")?;
    } else {
        write_taira_pidfd_preflight(&mut start_file)?;
    }
    writeln!(
        start_file,
        "DEFAULT_IROHAD_BIN_DEBUG={default_irohad_debug}"
    )?;
    writeln!(
        start_file,
        "DEFAULT_IROHAD_BIN_RELEASE={default_irohad_release}"
    )?;
    writeln!(start_file, "DEFAULT_IROHA_CLI_DEBUG={default_iroha_debug}")?;
    writeln!(
        start_file,
        "DEFAULT_IROHA_CLI_RELEASE={default_iroha_release}"
    )?;
    writeln!(start_file, "if [ -z \"${{IROHAD_BIN:-}}\" ]; then")?;
    writeln!(
        start_file,
        "  if [ -x \"$DEFAULT_IROHAD_BIN_DEBUG\" ]; then"
    )?;
    writeln!(start_file, "    IROHAD_BIN=\"$DEFAULT_IROHAD_BIN_DEBUG\"")?;
    writeln!(
        start_file,
        "  elif [ -x \"$DEFAULT_IROHAD_BIN_RELEASE\" ]; then"
    )?;
    writeln!(start_file, "    IROHAD_BIN=\"$DEFAULT_IROHAD_BIN_RELEASE\"")?;
    writeln!(
        start_file,
        "  else\n    echo \"IROHAD_BIN not set and default ($DEFAULT_IROHAD_BIN_DEBUG or $DEFAULT_IROHAD_BIN_RELEASE) not found; build iroha3d or set IROHAD_BIN\" >&2\n    exit 1\n  fi"
    )?;
    writeln!(start_file, "fi")?;
    writeln!(
        start_file,
        "echo \"Using IROHAD_BIN=$IROHAD_BIN\" >&2\nIROHAD_BIN_RESOLVED=\"$(command -v \"$IROHAD_BIN\" 2>/dev/null || true)\"\nif [ -z \"$IROHAD_BIN_RESOLVED\" ]; then\n  echo \"iroha3d binary not executable: $IROHAD_BIN\" >&2\n  exit 1\nfi\nIROHAD_BIN_DIR=\"$(cd -- \"$(dirname -- \"$IROHAD_BIN_RESOLVED\")\" && pwd)\"\nIROHA_CLI_FROM_IROHAD=\"$IROHAD_BIN_DIR/iroha\""
    )?;
    writeln!(start_file, "IROHA_CLI=\"${{IROHA_CLI:-}}\"")?;
    writeln!(start_file, "if [ -z \"$IROHA_CLI\" ]; then")?;
    writeln!(start_file, "  if [ -x \"$IROHA_CLI_FROM_IROHAD\" ]; then")?;
    writeln!(start_file, "    IROHA_CLI=\"$IROHA_CLI_FROM_IROHAD\"")?;
    writeln!(
        start_file,
        "  elif [ -x \"$DEFAULT_IROHA_CLI_RELEASE\" ]; then"
    )?;
    writeln!(start_file, "    IROHA_CLI=\"$DEFAULT_IROHA_CLI_RELEASE\"")?;
    writeln!(
        start_file,
        "  elif [ -x \"$DEFAULT_IROHA_CLI_DEBUG\" ]; then"
    )?;
    writeln!(start_file, "    IROHA_CLI=\"$DEFAULT_IROHA_CLI_DEBUG\"")?;
    writeln!(start_file, "  fi")?;
    writeln!(start_file, "fi")?;
    writeln!(
        start_file,
        "if [ -n \"$IROHA_CLI\" ] && [ ! -x \"$IROHA_CLI\" ]; then"
    )?;
    writeln!(
        start_file,
        "  echo \"iroha CLI not executable: $IROHA_CLI\" >&2"
    )?;
    writeln!(start_file, "  exit 1")?;
    writeln!(start_file, "fi")?;
    writeln!(start_file, "FAUCET_ACCOUNT={client_account_literal}")?;
    writeln!(
        start_file,
        "FAUCET_ASSET_DEFINITION_ID={fee_asset_definition_id}"
    )?;
    if !taira {
        writeln!(
            start_file,
            "command -v python3 >/dev/null 2>&1 || {{ echo \"python3 is required before starting localnet validators\" >&2; exit 1; }}"
        )?;
    }
    writeln!(start_file, "for i in $SELECTED_PEERS; do")?;
    writeln!(
        start_file,
        "  SNAPSHOT_STORE_DIR=\"$DIR/state/peer${{i}}/snapshot\""
    )?;
    // The first boot of a peer's consensus key: no safety record exists yet (Sumeragi §7.4).
    writeln!(start_file, "  FRESH_KEY_ARG=\"\"")?;
    writeln!(
        start_file,
        "  if [ ! -d \"$DIR/state/peer${{i}}/{LOCALNET_SUMERAGI_RECORDS_DIR}\" ]; then FRESH_KEY_ARG=\"--sumeragi-assert-fresh-key\"; fi"
    )?;
    if taira {
        writeln!(
            start_file,
            "  PROCESS_RECORD=\"$DIR/peer${{i}}.process.json\""
        )?;
    } else {
        writeln!(start_file, "  PIDFILE=\"$DIR/peer${{i}}.pid\"")?;
        writeln!(start_file, "  if [ -f \"$PIDFILE\" ]; then")?;
        writeln!(
            start_file,
            "    existing_pid=\"$(cat \"$PIDFILE\" 2>/dev/null || true)\""
        )?;
        writeln!(
            start_file,
            "    if [ -n \"$existing_pid\" ] && pid_is_running \"$existing_pid\"; then"
        )?;
        writeln!(
            start_file,
            "      echo \"peer$i already running with pid $existing_pid\" >&2"
        )?;
        writeln!(start_file, "      exit 1")?;
        writeln!(start_file, "    fi")?;
        writeln!(start_file, "    rm -f \"$PIDFILE\"")?;
        writeln!(start_file, "  fi")?;
    }
    writeln!(start_file, "  mkdir -p \"$SNAPSHOT_STORE_DIR/generations\"")?;
    writeln!(start_file, "  if command -v python3 >/dev/null 2>&1; then")?;
    writeln!(
        start_file,
        "    peer_pid=$(SNAPSHOT_STORE_DIR=\"$SNAPSHOT_STORE_DIR\" LOG_LEVEL=\"${{LOG_LEVEL:-info}}\" LOG_FILTER=\"${{LOG_FILTER:-}}\" IROHAD_BIN=\"$IROHAD_BIN\" IROHA_NETWORK_DIR=\"$DIR\" IROHA_PEER_INDEX=\"$i\" IROHA_PEER_CONFIG=\"${{BEACON_CONFIG:-$DIR/peer${{i}}.toml}}\" IROHA_PEER_LOG=\"$DIR/peer${{i}}.log\" IROHA_PEER_PROCESS_RECORD=\"${{PROCESS_RECORD:-}}\" IROHA_SORA_MODE=\"{sora_mode_env}\" IROHA_TAIRA_MODE=\"{taira_mode_env}\" IROHA_PEER_FRESH_KEY=\"$FRESH_KEY_ARG\" python3 - \"$BEACON_CONFIG\" \"$BEACON_CREDENTIAL\" \"$KAGAMI_BIN\" <<'PY'"
    )?;
    writeln!(start_file, "import os")?;
    writeln!(start_file, "import stat")?;
    writeln!(start_file, "import subprocess")?;
    writeln!(start_file, "import sys")?;
    if taira {
        start_file.write_all(TAIRA_PROCESS_IDENTITY_PY.as_bytes())?;
    }
    writeln!(start_file)?;
    writeln!(start_file, "env = os.environ.copy()")?;
    if taira {
        writeln!(
            start_file,
            "env[\"IROHAD_BIN\"] = os.path.realpath(env[\"IROHAD_BIN\"])"
        )?;
    }
    writeln!(start_file, "cmd = [env[\"IROHAD_BIN\"]]")?;
    writeln!(start_file, "if env.get(\"IROHA_SORA_MODE\") == \"1\":")?;
    writeln!(start_file, "    cmd.append(\"--sora\")")?;
    writeln!(
        start_file,
        "cmd.extend([\"--config\", env[\"IROHA_PEER_CONFIG\"]])"
    )?;
    if taira {
        start_file.write_all(TAIRA_BEACON_SELECTION_PY.as_bytes())?;
        writeln!(start_file, "selection = None")?;
        writeln!(start_file, "if sys.argv[1]:")?;
        writeln!(
            start_file,
            "    selection = select_taira_beacon_launch(env, *sys.argv[1:])"
        )?;
        writeln!(
            start_file,
            "    cmd.extend([\"--config-blake3\", selection[\"config_blake3\"]])"
        )?;
    }
    writeln!(start_file, "if env.get(\"IROHA_PEER_FRESH_KEY\"):")?;
    writeln!(start_file, "    cmd.append(env[\"IROHA_PEER_FRESH_KEY\"])")?;
    if taira {
        writeln!(
            start_file,
            "preflight_taira_start(env[\"IROHA_PEER_PROCESS_RECORD\"], int(env[\"IROHA_PEER_INDEX\"]), cmd)"
        )?;
    }
    if taira {
        start_file.write_all(TAIRA_RUNTIME_LAUNCH_PY.as_bytes())?;
        writeln!(start_file, "records = [")?;
        writeln!(
            start_file,
            "    (os.path.join(env[\"IROHA_NETWORK_DIR\"], \"runtime\", \"{TAIRA_RUNTIME_SIGNER_DIRECTORY}\", \"peer{{}}.private_key\".format(env[\"IROHA_PEER_INDEX\"])), os.path.join(env[\"IROHA_NETWORK_DIR\"], \"runtime\", \"{TAIRA_RUNTIME_SIGNER_DIRECTORY}\", \"peer{{}}.fd198\".format(env[\"IROHA_PEER_INDEX\"])), 71, 198),"
        )?;
        writeln!(start_file, "]")?;
        writeln!(start_file, "if selection is not None:")?;
        writeln!(start_file, "    credential = selection[\"sources\"][1]")?;
        writeln!(
            start_file,
            "    records.append((credential[\"path\"], os.path.join(os.path.dirname(credential[\"path\"]), \"peer{{}}.fd200\".format(env[\"IROHA_PEER_INDEX\"])), credential[\"size\"], 200))"
        )?;
        writeln!(
            start_file,
            "process = launch_taira_process(cmd, env, records, selection)"
        )?;
    } else {
        writeln!(
            start_file,
            "with open(env[\"IROHA_PEER_LOG\"], \"ab\", buffering=0) as log:"
        )?;
        writeln!(
            start_file,
            "    process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, close_fds=True, start_new_session=True)"
        )?;
    }
    writeln!(start_file, "print(process.pid)")?;
    writeln!(start_file, "PY")?;
    writeln!(start_file, "    )")?;
    writeln!(start_file, "  else")?;
    if taira {
        writeln!(
            start_file,
            "    echo \"python3 is required to pass the Taira signer through fixed FD 198\" >&2"
        )?;
        writeln!(start_file, "    exit 1")?;
    } else {
        writeln!(
            start_file,
            "    echo \"python3 is required to launch localnet validators\" >&2"
        )?;
        writeln!(start_file, "    exit 1")?;
    }
    writeln!(start_file, "  fi")?;
    if taira {
        writeln!(
            start_file,
            "  echo \"peer$i exact process identity captured in $PROCESS_RECORD\""
        )?;
    } else {
        writeln!(start_file, "  echo \"$peer_pid\" > \"$PIDFILE\"")?;
        writeln!(start_file, "  echo \"peer$i pid $(cat \"$PIDFILE\")\"")?;
    }
    writeln!(start_file, "done")?;
    writeln!(
        start_file,
        "echo \"Faucet uses its explicit genesis allocation of $FAUCET_ASSET_DEFINITION_ID at $FAUCET_ACCOUNT; startup does not issue assets.\" >&2"
    )?;
    Ok(start_file.flush()?)
}
fn write_stop_script(stop: &Path, peers: u16, taira: bool) -> Result<()> {
    let mut stop_file = BufWriter::new(custody::create_file(stop)?);
    writeln!(stop_file, "#!/usr/bin/env bash")?;
    writeln!(stop_file, "set -euo pipefail")?;
    writeln!(stop_file, "umask 077")?;
    writeln!(stop_file, "DIR=$(cd \"$(dirname \"$0\")\" && pwd)")?;
    writeln!(stop_file, "PEER_COUNT={peers}")?;
    writeln!(
        stop_file,
        "SELECTED_PEERS=\"$(seq 0 \"$((PEER_COUNT - 1))\")\""
    )?;
    if taira {
        write_taira_launch_arguments(&mut stop_file, false)?;
    } else {
        writeln!(stop_file, "if [ \"$#\" -ne 0 ]; then")?;
        writeln!(
            stop_file,
            "  if [ \"$#\" -ne 2 ] || [ \"$1\" != \"--peer-index\" ]; then"
        )?;
        writeln!(stop_file, "    echo \"usage: $0 [--peer-index INDEX]\" >&2")?;
        writeln!(stop_file, "    exit 2")?;
        writeln!(stop_file, "  fi")?;
        writeln!(
            stop_file,
            "  if [[ ! $2 =~ ^(0|[1-9][0-9]{{0,4}})$ ]]; then"
        )?;
        writeln!(stop_file, "    echo \"invalid peer index: $2\" >&2")?;
        writeln!(stop_file, "    exit 2")?;
        writeln!(stop_file, "  fi")?;
        writeln!(stop_file, "  peer_index=$((10#$2))")?;
        writeln!(stop_file, "  if (( peer_index >= PEER_COUNT )); then")?;
        writeln!(stop_file, "    echo \"invalid peer index: $2\" >&2")?;
        writeln!(stop_file, "    exit 2")?;
        writeln!(stop_file, "  fi")?;
        writeln!(stop_file, "  SELECTED_PEERS=\"$peer_index\"")?;
        writeln!(stop_file, "fi")?;
    }
    if taira {
        write_taira_pidfd_preflight(&mut stop_file)?;
        writeln!(stop_file, "for i in $SELECTED_PEERS; do")?;
        writeln!(
            stop_file,
            "  PROCESS_RECORD=\"$DIR/peer${{i}}.process.json\""
        )?;
        writeln!(
            stop_file,
            "  if [ ! -e \"$PROCESS_RECORD\" ] && [ ! -L \"$PROCESS_RECORD\" ]; then continue; fi"
        )?;
        writeln!(
            stop_file,
            "  IROHA_PEER_INDEX=\"$i\" IROHA_PEER_CONFIG=\"${{BEACON_CONFIG:-$DIR/peer${{i}}.toml}}\" IROHA_PEER_PROCESS_RECORD=\"$PROCESS_RECORD\" python3 - <<'PY'"
        )?;
        writeln!(stop_file, "import os")?;
        writeln!(stop_file, "import stat")?;
        stop_file.write_all(TAIRA_PROCESS_IDENTITY_PY.as_bytes())?;
        writeln!(stop_file, "env = os.environ")?;
        writeln!(
            stop_file,
            "stop_taira_process(env[\"IROHA_PEER_PROCESS_RECORD\"], int(env[\"IROHA_PEER_INDEX\"]), env[\"IROHA_PEER_CONFIG\"])"
        )?;
        writeln!(stop_file, "PY")?;
        writeln!(stop_file, "done")?;
        return Ok(stop_file.flush()?);
    }
    writeln!(stop_file, "pid_matches_peer() {{")?;
    writeln!(stop_file, "  pid=\"$1\"")?;
    writeln!(stop_file, "  config=\"$2\"")?;
    writeln!(
        stop_file,
        "  case \"$pid\" in ''|*[!0-9]*) return 1 ;; esac"
    )?;
    writeln!(stop_file, "  command -v ps >/dev/null 2>&1 || return 0")?;
    writeln!(
        stop_file,
        "  command_line=\"$(ps -p \"$pid\" -o command= 2>/dev/null || true)\""
    )?;
    writeln!(stop_file, "  [ -n \"$command_line\" ] || return 1")?;
    writeln!(
        stop_file,
        "  printf '%s' \"$command_line\" | grep -F -- \"--config $config\" >/dev/null \\"
    )?;
    writeln!(
        stop_file,
        "    || printf '%s' \"$command_line\" | grep -F -- \"--config=$config\" >/dev/null"
    )?;
    writeln!(stop_file, "}}")?;
    writeln!(stop_file, "pid_is_running() {{")?;
    writeln!(stop_file, "  pid=\"$1\"")?;
    writeln!(
        stop_file,
        "  case \"$pid\" in ''|*[!0-9]*) return 1 ;; esac"
    )?;
    writeln!(stop_file, "  command -v ps >/dev/null 2>&1 || return 1")?;
    writeln!(stop_file, "  ps -p \"$pid\" -o pid= >/dev/null 2>&1")?;
    writeln!(stop_file, "}}")?;
    writeln!(stop_file, "for i in $SELECTED_PEERS; do")?;
    writeln!(stop_file, "  pidfile=\"$DIR/peer${{i}}.pid\"")?;
    writeln!(stop_file, "  [ -f \"$pidfile\" ] || continue")?;
    writeln!(
        stop_file,
        "  pid=\"$(cat \"$pidfile\" 2>/dev/null || true)\""
    )?;
    writeln!(stop_file, "  if [ -z \"$pid\" ]; then")?;
    writeln!(stop_file, "    rm -f \"$pidfile\"")?;
    writeln!(stop_file, "    continue")?;
    writeln!(stop_file, "  fi")?;
    writeln!(stop_file, "  case \"$pid\" in")?;
    writeln!(stop_file, "    ''|*[!0-9]*)")?;
    writeln!(
        stop_file,
        "      echo \"removing malformed pidfile $pidfile (pid=$pid)\" >&2"
    )?;
    writeln!(stop_file, "      rm -f \"$pidfile\"")?;
    writeln!(stop_file, "      continue")?;
    writeln!(stop_file, "      ;;")?;
    writeln!(stop_file, "  esac")?;
    writeln!(stop_file, "  if ! pid_is_running \"$pid\"; then")?;
    writeln!(stop_file, "    rm -f \"$pidfile\"")?;
    writeln!(stop_file, "    continue")?;
    writeln!(stop_file, "  fi")?;
    writeln!(stop_file, "  peer_name=\"$(basename \"$pidfile\" .pid)\"")?;
    writeln!(stop_file, "  config=\"$DIR/${{peer_name}}.toml\"")?;
    writeln!(
        stop_file,
        "  if ! pid_matches_peer \"$pid\" \"$config\"; then"
    )?;
    writeln!(
        stop_file,
        "    echo \"leaving $pidfile in place: live pid $pid does not match $config\" >&2"
    )?;
    writeln!(stop_file, "    continue")?;
    writeln!(stop_file, "  fi")?;
    writeln!(stop_file, "  kill \"$pid\" 2>/dev/null || true")?;
    writeln!(stop_file, "  for _ in $(seq 1 40); do")?;
    writeln!(stop_file, "    if pid_is_running \"$pid\"; then")?;
    writeln!(stop_file, "      sleep 0.25")?;
    writeln!(stop_file, "    else")?;
    writeln!(stop_file, "      break")?;
    writeln!(stop_file, "    fi")?;
    writeln!(stop_file, "  done")?;
    writeln!(stop_file, "  if pid_is_running \"$pid\"; then")?;
    writeln!(
        stop_file,
        "    echo \"leaving $pidfile in place: localnet peer $peer_name pid $pid is still running\" >&2"
    )?;
    writeln!(stop_file, "    continue")?;
    writeln!(stop_file, "  fi")?;
    writeln!(stop_file, "  rm -f \"$pidfile\"")?;
    writeln!(stop_file, "done")?;
    Ok(stop_file.flush()?)
}
fn copy_rans_tables(out_dir: &Path) -> Result<PathBuf> {
    let canonical_out_dir = fs::canonicalize(out_dir).wrap_err_with(|| {
        format!(
            "failed to canonicalize localnet output directory {}",
            out_dir.display()
        )
    })?;
    let repo_root = repo_root_path();
    let src = repo_root.join("codec/rans/tables");
    let dest = out_dir.join("codec/rans/tables");
    custody::ensure_directory(&dest)
        .wrap_err_with(|| format!("failed to create rANS tables directory {}", dest.display()))?;
    let mut copied_seed = false;
    if let Ok(entries) = fs::read_dir(&src) {
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let fname = entry.file_name();
                if fname == "rans_seed0.toml" {
                    copied_seed = true;
                }
                custody::write(
                    dest.join(fname),
                    iroha_fs::read_regular(entry.path(), 16 * 1024 * 1024)?.as_slice(),
                )
                .wrap_err("copy rANS table file")?;
            }
        }
    }
    let seed_path = out_dir.join(LOCALNET_RANS_TABLE_RELATIVE_PATH);
    if !copied_seed {
        custody::write(&seed_path, RANS_SEED0_TABLE).wrap_err("write embedded rANS table")?;
    }
    let canonical_seed_path = fs::canonicalize(&seed_path).wrap_err_with(|| {
        format!(
            "failed to canonicalize generated rANS table {}",
            seed_path.display()
        )
    })?;
    if !canonical_seed_path.starts_with(&canonical_out_dir) {
        return Err(eyre!(
            "generated rANS table escaped localnet output directory: {}",
            canonical_seed_path.display()
        ));
    }
    Ok(canonical_seed_path)
}
/// Local account domain for the operator alias, onboarding credential scope and onboarding
/// permissions. Client configurations carry no account domain.
const CLIENT_ACCOUNT_DOMAIN: &str = "wonderland.universal";
const CLIENT_ACCOUNT_PUBLIC: &str =
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
#[cfg(test)]
const CLIENT_ACCOUNT_PRIVATE: &str =
    "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53";
/// Public genesis verifier key emitted for runtime configuration.
pub const GENESIS_PUBLIC_KEY_FILE: &str = "genesis.public_key";
/// Exact signed-genesis consensus-header hash emitted for runtime configuration.
pub const GENESIS_EXPECTED_HASH_FILE: &str = "genesis.expected_hash";
/// Owner-only genesis signing key emitted for offline custody.
pub const GENESIS_PRIVATE_KEY_FILE: &str = "genesis.private_key";
struct LocalnetClientIdentity {
    account_id: AccountId,
    public_key: iroha_crypto::PublicKey,
    private_key: Zeroizing<String>,
}
impl LocalnetClientIdentity {
    fn account_literal(&self, chain_discriminant: Option<u16>) -> String {
        account_id_runtime_literal(&self.account_id, chain_discriminant)
    }
}
struct LocalnetRuntimeBundle {
    ledger_signer_key: PathBuf,
    operator_signer_key: PathBuf,
    onboarding_signer_key: PathBuf,
    onboarding_token_file: PathBuf,
    onboarding_token_hash: [u8; 32],
}
impl LocalnetRuntimeBundle {
    fn at_root(&self, root: &Path) -> Self {
        let runtime = root.join(LOCALNET_RUNTIME_DIRECTORY);
        Self {
            ledger_signer_key: runtime.join(LOCALNET_LEDGER_SIGNER_KEY_FILE),
            operator_signer_key: runtime.join(LOCALNET_OPERATOR_SIGNER_KEY_FILE),
            onboarding_signer_key: runtime.join(LOCALNET_ONBOARDING_SIGNER_KEY_FILE),
            onboarding_token_file: runtime.join(LOCALNET_ONBOARDING_TOKEN_FILE),
            onboarding_token_hash: self.onboarding_token_hash,
        }
    }
}
fn localnet_ephemeral_identity(
    base_seed: Option<&[u8]>,
    identity_label: &[u8],
) -> Result<LocalnetClientIdentity> {
    let (public_key, private_key) = generate_account_key_pair(base_seed, identity_label)?;
    Ok(LocalnetClientIdentity {
        account_id: AccountId::new(public_key.clone()),
        public_key,
        private_key: Zeroizing::new(private_key.to_string()),
    })
}
fn write_private_key_sidecar(path: &Path, private_key: &str) -> Result<()> {
    let mut contents = Zeroizing::new(Vec::with_capacity(private_key.len() + 1));
    contents.extend_from_slice(private_key.as_bytes());
    contents.push(b'\n');
    crate::localnet::custody::write_private_file_atomic(path, contents.as_slice())
        .wrap_err_with(|| format!("write private signer key {}", path.display()))
}
fn write_localnet_runtime_bundle(
    out_dir: &Path,
    ledger: &LocalnetClientIdentity,
    http_operator: &LocalnetClientIdentity,
    onboarding: &LocalnetClientIdentity,
) -> Result<LocalnetRuntimeBundle> {
    ensure!(
        ledger.public_key != http_operator.public_key
            && ledger.public_key != onboarding.public_key
            && http_operator.public_key != onboarding.public_key,
        "localnet ledger, HTTP operator and onboarding signers must be distinct"
    );
    let runtime_dir = out_dir.join(LOCALNET_RUNTIME_DIRECTORY);
    let runtime_dir = crate::localnet::custody::prepare_empty_private_directory(&runtime_dir)
        .wrap_err("prepare localnet runtime credential directory")?;
    let ledger_signer_key = runtime_dir.join(LOCALNET_LEDGER_SIGNER_KEY_FILE);
    let operator_signer_key = runtime_dir.join(LOCALNET_OPERATOR_SIGNER_KEY_FILE);
    let onboarding_signer_key = runtime_dir.join(LOCALNET_ONBOARDING_SIGNER_KEY_FILE);
    let onboarding_token_file = runtime_dir.join(LOCALNET_ONBOARDING_TOKEN_FILE);
    write_private_key_sidecar(&ledger_signer_key, ledger.private_key.as_str())?;
    write_private_key_sidecar(&operator_signer_key, http_operator.private_key.as_str())?;
    write_private_key_sidecar(&onboarding_signer_key, onboarding.private_key.as_str())?;
    let mut token_entropy = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut token_entropy)
        .wrap_err("obtain OS entropy for the localnet onboarding token")?;
    let token = Zeroizing::new(format!("iroha-localnet-{}", hex::encode(token_entropy)));
    token_entropy.zeroize();
    let onboarding_token_hash = *blake3::hash(token.as_bytes()).as_bytes();
    crate::localnet::custody::write_private_file_atomic(&onboarding_token_file, token.as_bytes())
        .wrap_err("write localnet onboarding token")?;
    Ok(LocalnetRuntimeBundle {
        ledger_signer_key,
        operator_signer_key,
        onboarding_signer_key,
        onboarding_token_file,
        onboarding_token_hash,
    })
}
fn taira_runtime_signer_key_path(directory: &Path, peer_index: usize) -> PathBuf {
    directory.join(format!("peer{peer_index}.private_key"))
}
fn write_taira_runtime_signer_keys(out_dir: &Path, peers: &[Peer]) -> Result<()> {
    let directory = out_dir.join("runtime").join(TAIRA_RUNTIME_SIGNER_DIRECTORY);
    let directory = crate::localnet::custody::prepare_empty_private_directory(&directory)
        .wrap_err("prepare Taira runtime signer directory")?;
    for (peer_index, peer) in peers.iter().enumerate() {
        let literal = Zeroizing::new(
            peer.runtime_signer_private_key
                .try_to_multihash_string()
                .wrap_err("encode canonical Taira runtime signer key")?,
        );
        write_private_key_sidecar(
            &taira_runtime_signer_key_path(&directory, peer_index),
            literal.as_str(),
        )?;
    }
    Ok(())
}
fn managed_node_dir(out_dir: &Path, peer_index: usize) -> PathBuf {
    out_dir.join("nodes").join(format!("peer{peer_index}"))
}

fn prepare_managed_node_directories(out_dir: &Path, peer_count: usize) -> Result<()> {
    let nodes = iroha_fs::PrivateDirectory::open_or_create(&out_dir.join("nodes"))?;
    for index in 0..peer_count {
        nodes.create_child(&format!("peer{index}"))?;
    }
    Ok(())
}

fn managed_peer_config(rendered: &str, data_dir: &Path) -> Result<Zeroizing<String>> {
    use toml::Value;
    let mut table = crate::secret_toml::Table::new(crate::secret_toml::parse_table(
        rendered,
        "managed validator configuration",
    )?);
    table.insert(
        "data_dir".into(),
        Value::String(data_dir.to_string_lossy().into_owned()),
    );
    ensure!(
        table.get("sumeragi").and_then(Value::as_table).is_some(),
        "generated validator configuration has no sumeragi section"
    );
    managed_puzzle::apply_if_loopback(&mut table);
    toml::to_string(&*table)
        .map(Zeroizing::new)
        .map_err(|_| eyre!("cannot encode managed validator configuration"))
}

#[cfg(test)]
mod managed_tests {
    use super::*;

    #[test]
    fn managed_preparation_binds_four_native_configs_and_a_private_client() {
        let _resources = crate::managed::native_test_guard();
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap().join("bundle");
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = prepare_localnet("local", &root, &ports).unwrap();
        assert_eq!(prepared.peers.len(), 4);
        assert_eq!(prepared.context.name, "local");
        assert_eq!(
            prepared.build_cache_root(),
            root.join("runtime/build-cache")
        );
        assert!(!prepared.build_cache_root().exists());
        let mut another_generation = prepared.clone();
        another_generation.context.client_config = root.join("next/client.toml");
        assert_ne!(
            prepared.build_cache_root(),
            another_generation.build_cache_root()
        );
        assert!(!another_generation.build_cache_root().exists());
        assert!(
            !root.join("next").exists(),
            "path intent must not create a generation"
        );
        assert_eq!(prepared.context.dataspace_alias, "universal");
        assert_eq!(prepared.context.dataspace_id, 0);
        let config = prepared.context.load_client_config().unwrap();
        assert_eq!(
            prepared.service_profile,
            LocalnetServiceProfile::StreamTokenAuthorities
        );
        let authorities = prepared.stream_token_authorities().unwrap().unwrap();
        assert_eq!(authorities.network.authorities.len(), 3);
        assert_eq!(authorities.providers.len(), 3);
        for provider in &authorities.providers {
            assert_eq!(
                provider.authorities.len(),
                10,
                "every original provider holds its ten fixed service roles"
            );
        }
        assert_eq!(authorities.network_id, config.network_id);
        assert_eq!(authorities.manager, config.account);
        let operator = prepared.load_operator_key_pair().unwrap();
        assert_ne!(operator.public_key(), config.key_pair.public_key());
        for (index, peer) in prepared.peers.iter().enumerate() {
            let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024).unwrap();
            let table: toml::Table = std::str::from_utf8(&bytes).unwrap().parse().unwrap();
            let config = parse_localnet_peer_config(
                std::str::from_utf8(&bytes).unwrap(),
                Some(&peer.config_path),
            )
            .unwrap();
            assert_eq!(table["zk"]["pipa_r"]["enabled"].as_bool(), Some(true));
            assert!(table["zk"].get("halo2").is_none());
            assert!(config.zk.pipa_r.enabled);
            let retired = Zeroizing::new(format!(
                "{}\n[zk.halo2]\nenabled = true\n",
                std::str::from_utf8(&bytes).unwrap()
            ));
            assert!(parse_localnet_peer_config(&retired, Some(&peer.config_path)).is_err());
            assert_eq!(
                parse_localnet_peer_config(
                    std::str::from_utf8(&bytes).unwrap(),
                    Some(&peer.config_path),
                )
                .map(|retry| retry.genesis.expected_hash)
                .unwrap(),
                config.genesis.expected_hash,
                "the same original generated config remains admissible after retired-field refusal"
            );
            assert!(!config.torii.sorafs_storage.stream_tokens.enabled);
            assert!(config.torii.sorafs_storage.stream_tokens.signer.is_none());
            assert!(
                config
                    .torii
                    .sorafs_storage
                    .stream_tokens
                    .admission_native
                    .is_none()
            );
            assert_eq!(
                config.network.connect_startup_delay,
                std::time::Duration::ZERO
            );
            assert_eq!(
                (config.network.dial_timeout, config.network.preauth_timeout),
                (
                    iroha_config::parameters::defaults::network::DIAL_TIMEOUT,
                    iroha_config::parameters::defaults::network::PREAUTH_TIMEOUT,
                )
            );
            managed_puzzle::assert_managed_profile(&table, &config.network.soranet_handshake.pow);
            let node = managed_node_dir(&root, index);
            assert_eq!(table["data_dir"].as_str(), node.to_str());
            assert!(table["sumeragi"].get("mint_finality_seed_fd").is_none());
            assert_eq!(
                table["nexus"]["storage"]["local_budget_bytes"].as_integer(),
                Some(LOCALNET_NEXUS_STORAGE_BUDGET_BYTES as i64),
                "every managed validator needs its finite developer storage cap"
            );
            let node = iroha_fs::PrivateDirectory::open(node).unwrap();
            assert!(!node.path().join("secrets/mint_finality.seed").exists());
        }
        assert!(!root.join("start.sh").exists());
        assert!(!root.join("stop.sh").exists());
        assert!(prepare_localnet("local", &root, &ports).is_err());
        assert_eq!(ports.reserved_count(), 8);
        let runtime =
            iroha_fs::PrivateDirectory::open(root.join(LOCALNET_RUNTIME_DIRECTORY)).unwrap();
        runtime
            .write_atomic(
                LOCALNET_OPERATOR_SIGNER_KEY_FILE,
                b"malformed-secret\n",
                iroha_fs::PublishMode::Replace,
            )
            .unwrap();
        let error = prepared.load_operator_key_pair().unwrap_err().to_string();
        assert!(!error.contains("malformed-secret"));
    }

    #[test]
    fn native_layout_uses_data_dir_without_inherited_descriptor() {
        let source = "chain = 'local'\n[sumeragi]\nrole = 'validator'\n";
        let directory = Path::new("/private/runtime/peer0");
        let rendered = managed_peer_config(source, directory).unwrap();
        let table = rendered.parse::<toml::Table>().unwrap();
        assert_eq!(table["data_dir"].as_str(), directory.to_str());
        assert_eq!(table["sumeragi"]["role"].as_str(), Some("validator"));
        assert!(
            table["sumeragi"]
                .as_table()
                .unwrap()
                .get("mint_finality_seed_fd")
                .is_none()
        );
        assert!(managed_peer_config("[other]\nx=1", directory).is_err());
    }

    #[test]
    fn managed_generation_creates_private_node_directories_without_retired_seeds() {
        let temporary = localnet_test_helpers::private_tempdir().unwrap();
        let directory = temporary.path().canonicalize().unwrap();
        prepare_managed_node_directories(&directory, 4).unwrap();
        for index in 0..4 {
            let node =
                iroha_fs::PrivateDirectory::open(managed_node_dir(&directory, index)).unwrap();
            assert!(node.path().read_dir().unwrap().next().is_none());
            node.revalidate().unwrap();
        }
        assert!(!directory.join("runtime/mint-finality-signers").exists());
        assert!(prepare_managed_node_directories(&directory, 4).is_err());
    }
}

fn write_localnet_gitignore(out_dir: &Path) -> Result<()> {
    let path = out_dir.join(".gitignore");
    custody::write(
        &path,
        concat!(
            "# Kagami localnets contain private signing material and runtime tokens.\n",
            "*\n",
            "!.gitignore\n",
        ),
    )
    .wrap_err_with(|| format!("write protective ignore file {}", path.display()))
}
#[cfg(test)]
#[path = "localnet/client_identity_test_support.rs"]
mod localnet_test_helpers;
#[cfg(test)]
#[path = "localnet/native_lane_policy_tests.rs"]
mod native_lane_policy_tests;
#[cfg(test)]
#[path = "localnet/profile_golden_parity_tests.rs"]
mod profile_golden_parity_tests;
#[cfg(test)]
use localnet_test_helpers::localnet_client_identity;
/// Public fixture account used only as a placeholder before real client identity substitution.
pub fn localnet_client_account_id() -> AccountId {
    let public_key = CLIENT_ACCOUNT_PUBLIC
        .parse()
        .expect("localnet client public key must parse");
    AccountId::new(public_key)
}
fn write_owner_only_localnet_file(path: &Path, contents: &[u8]) -> Result<()> {
    crate::localnet::custody::write_private_file_atomic(path, contents)
        .wrap_err_with(|| format!("write owner-only localnet file {}", path.display()))
}
/// Write the operator client configuration.
///
/// Its account network context is always explicit: the configured chain prefix, or the node
/// default that peers rendered without `chain_discriminant` run with.
fn write_client_config(
    out_dir: &Path,
    base_api_port: u16,
    torii_host: &CanonicalHost,
    chain_id: &str,
    chain_discriminant: Option<u16>,
    client: &LocalnetClientIdentity,
    publication: Option<&toml::Table>,
) -> Result<()> {
    let path = out_dir.join("client.toml");
    let rendered = render_client_config(
        base_api_port,
        torii_host,
        chain_id,
        chain_discriminant,
        client,
        publication,
    )?;
    write_owner_only_localnet_file(&path, rendered.as_bytes())
        .wrap_err_with(|| format!("write localnet client config {}", path.display()))
}
fn render_client_config(
    base_api_port: u16,
    torii_host: &CanonicalHost,
    chain_id: &str,
    chain_discriminant: Option<u16>,
    client: &LocalnetClientIdentity,
    publication: Option<&toml::Table>,
) -> Result<Zeroizing<String>> {
    // Render explicitly to avoid pretty-printer wrapping the long keys.
    let torii_host = torii_host.url_host();
    let chain_discriminant = chain_discriminant
        .unwrap_or_else(iroha_config::parameters::defaults::common::chain_discriminant);
    let mut rendered = Zeroizing::new(format!(
        concat!(
            "chain = \"{chain}\"\n",
            "network_id_file = \"{network_id_file}\"\n",
            "torii_url = \"http://{torii_host}:{torii_port}/\"\n",
            "\n",
            "[transaction]\n",
            "time_to_live_ms = {ttl_ms}\n",
            "status_timeout_ms = {status_timeout_ms}\n",
            "nonce = false\n",
            "\n",
            "[account]\n",
            "chain_discriminant = {chain_discriminant}\n",
            "private_key = \"{private_key}\"\n",
            "public_key  = \"{public_key}\"\n",
            "\n",
            "[basic_auth]\n",
            "password  = \"ilovetea\"\n",
            "web_login = \"mad_hatter\"\n",
        ),
        chain = chain_id,
        network_id_file = GENESIS_EXPECTED_HASH_FILE,
        torii_port = base_api_port,
        torii_host = torii_host,
        ttl_ms = LOCALNET_CLIENT_TTL_MS,
        status_timeout_ms = LOCALNET_CLIENT_STATUS_TIMEOUT_MS,
        chain_discriminant = chain_discriminant,
        private_key = client.private_key.as_str(),
        public_key = client.public_key,
    ));
    if let Some(publication) = publication {
        let musubi = toml::Table::from_iter([(
            "publication".into(),
            toml::Value::Table(publication.clone()),
        )]);
        let table = toml::Table::from_iter([("musubi".into(), toml::Value::Table(musubi))]);
        rendered.push('\n');
        rendered.push_str(&toml::to_string(&table)?);
    }
    Ok(rendered)
}
/// Describe the fresh SORA Taira lane and dataspace catalog committed into genesis.
fn taira_catalog_readme_note(out_dir: &Path) -> String {
    use std::fmt::Write as _;
    fn lane_list(lanes: impl IntoIterator<Item = u32>) -> String {
        lanes
            .into_iter()
            .map(|lane| lane.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
    let registered = lane_list(
        (0..=2).chain(
            TAIRA_PARTICIPANT_LANES
                .iter()
                .map(|participant| participant.lane_index),
        ),
    );
    let mut note = format!(
        "- Registered lanes: `{registered}`; lanes `0` core, `1` governance and `2` zk share dataspace `universal`, and each participant lane has its own dataspace\n"
    );
    let manifest_directory = out_dir.join("lane-manifests");
    for participant in TAIRA_PARTICIPANT_LANES {
        let admission = if participant.restricted() {
            format!(
                "restricted Parliament lane, manifest `{}`",
                manifest_directory
                    .join(format!("{}.manifest.json", participant.alias))
                    .display()
            )
        } else {
            "public lane with its own stake-elected validators".to_owned()
        };
        writeln!(
            note,
            "- Lane `{}` `{}`: {admission}; dataspace `{}` id `{}` (SNS name hash)",
            participant.lane_index,
            participant.alias,
            participant.alias,
            participant.dataspace_id().as_u64()
        )
        .expect("writing to a String cannot fail");
    }
    let public_validator_lanes = lane_list(
        localnet_public_validator_lanes(Some(SoraProfile::Nexus), true)
            .into_iter()
            .map(LaneId::as_u32),
    );
    writeln!(
        note,
        "- Public validator lanes: `{public_validator_lanes}`\n\
         - Retain the lane manifest directory `{}` with the generated peer configs\n\
         - Genesis registers no application assets; every asset receives a fresh id after genesis",
        manifest_directory.display()
    )
    .expect("writing to a String cannot fail");
    note
}
#[allow(clippy::too_many_arguments)]
fn write_localnet_readme(
    out_dir: &Path,
    chain_id: &str,
    seed: Option<&str>,
    consensus_mode: SumeragiConsensusMode,
    peers: u16,
    torii_url: &str,
    genesis_json_path: &Path,
    genesis_signed_path: &Path,
    genesis_expected_hash_path: &Path,
    genesis_public_key_path: &Path,
    genesis_private_key_path: &Path,
    client_config_path: &Path,
    start_path: &Path,
    stop_path: &Path,
    operator_account_id: &str,
    onboarding_account_id: &str,
    runtime_bundle: &LocalnetRuntimeBundle,
    alias_setup_intent_path: &Path,
    shell_out_dir: &str,
) -> Result<()> {
    let taira_catalog_note = if chain_id == PUBLIC_TAIRA_CHAIN_ID {
        taira_catalog_readme_note(out_dir)
    } else {
        String::new()
    };
    let readme_path = out_dir.join("README.md");
    let start_command = localnet_script_command("start.sh");
    let stop_command = localnet_script_command("stop.sh");
    let seed_line = seed
        .map(|seed| {
            format!(
                "- Base seed BLAKE3 fingerprint: `{}`\n",
                blake3::hash(seed.as_bytes()).to_hex()
            )
        })
        .unwrap_or_default();
    let profile_notes = concat!(
        "- Generated peer configs enable structural `torii.account_onboarding`\n",
        "- The signed BLS validator topology and original proofs of possession establish generation zero\n",
        "- Runtime credentials are owner-only files; read the token from its sidecar when calling sponsored onboarding\n\n",
        "Run `kagami docker` without `--seed` against this directory to validate the exact ",
        "validator identities, PoPs, signed body, verifier key, and expected hash as one ",
        "authoritative prepared bundle. The resulting Compose manifest embeds only read-only ",
        "paths to the three public runtime artifacts. The signing key is never mounted at ",
        "runtime; keep it offline and never commit it.\n\n",
    );
    let rendered = format!(
        concat!(
            "# Kagami Localnet\n\n",
            "- Chain ID: `{chain_id}`\n",
            "{seed_line}",
            "- Consensus mode: `{consensus_mode}`\n",
            "- Peer count: `{peers}`\n",
            "- Primary Torii URL: `{torii_url}`\n",
            "- Genesis JSON: `{genesis_json}`\n",
            "- Signed genesis: `{genesis_signed}`\n",
            "- Approved exact genesis hash: `{genesis_expected_hash}`\n",
            "- Genesis verifier key: `{genesis_public_key}`\n",
            "- Owner-held genesis signing key: `{genesis_private_key}`\n",
            "- Client config: `{client_config}`\n\n",
            "## Built-in App API bootstrap\n\n",
            "{taira_catalog_note}",
            "- Ephemeral ledger administrator: `{operator_account_id}`\n",
            "- Ephemeral onboarding authority: `{onboarding_account_id}`\n",
            "- Ledger/faucet signer sidecar: `{ledger_signer_key}`\n",
            "- Dedicated HTTP operator signer sidecar: `{operator_signer_key}`\n",
            "- Onboarding signer sidecar: `{onboarding_signer_key}`\n",
            "- Onboarding API token sidecar: `{onboarding_token_file}`\n",
            "- Secret-free alias setup intent: `{alias_setup_intent}`\n",
            "{profile_notes}",
            "- Start script: `{start_script}`\n",
            "- Stop script: `{stop_script}`\n\n",
            "## Next steps\n\n",
            "```bash\n",
            "cd {out_dir}\n",
            "{start_command}\n",
            "curl -sf {torii_url}health\n",
            "{stop_command}\n",
            "```\n",
            "Logs are written to `peerN.log` files next to the generated configs.\n",
        ),
        chain_id = chain_id,
        seed_line = seed_line,
        profile_notes = profile_notes,
        consensus_mode = consensus_mode_label(consensus_mode),
        peers = peers,
        torii_url = torii_url,
        genesis_json = genesis_json_path.display(),
        genesis_signed = genesis_signed_path.display(),
        genesis_expected_hash = genesis_expected_hash_path.display(),
        genesis_public_key = genesis_public_key_path.display(),
        genesis_private_key = genesis_private_key_path.display(),
        client_config = client_config_path.display(),
        taira_catalog_note = taira_catalog_note,
        operator_account_id = operator_account_id,
        onboarding_account_id = onboarding_account_id,
        ledger_signer_key = runtime_bundle.ledger_signer_key.display(),
        operator_signer_key = runtime_bundle.operator_signer_key.display(),
        onboarding_signer_key = runtime_bundle.onboarding_signer_key.display(),
        onboarding_token_file = runtime_bundle.onboarding_token_file.display(),
        alias_setup_intent = alias_setup_intent_path.display(),
        start_script = start_path.display(),
        stop_script = stop_path.display(),
        out_dir = shell_out_dir,
        start_command = start_command,
        stop_command = stop_command,
    );
    custody::write(&readme_path, rendered).wrap_err_with(|| {
        format!(
            "failed to write localnet guide to {}",
            readme_path.display()
        )
    })
}
fn localnet_script_command(script_name: &str) -> String {
    format!("bash ./{script_name}")
}
#[cfg(test)]
#[path = "localnet/tests.rs"]
mod tests;

/// Generate the stock managed four-validator Global sandbox and its service-authority prerequisites.
///
/// Original signed genesis binds the retained client and service roles. Token services remain disabled.
///
/// # Errors
/// Rejects unsafe custody, invalid generated configuration, and failed authenticated genesis.
pub fn prepare_localnet(
    name: &str,
    directory: &Path,
    ports: &crate::managed::LocalnetPorts,
) -> crate::managed::Result<crate::managed::PreparedLocalnet> {
    prepare_localnet_at(
        name,
        directory,
        ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
}

pub(crate) fn prepare_localnet_at(
    name: &str,
    directory: &Path,
    ports: &crate::managed::LocalnetPorts,
    service_profile: LocalnetServiceProfile,
    publication_root: Option<&Path>,
) -> crate::managed::Result<crate::managed::PreparedLocalnet> {
    use crate::managed::{Error, ManagedContext, ManagedPeer, PreparedLocalnet};
    generate_managed_localnet_at(
        &LocalnetOptions {
            service_profile,
            sora_profile: None,
            perf_profile: None,
            peers: NonZeroU16::new(4).expect("four is nonzero"),
            seed: None,
            bind_host: "127.0.0.1".into(),
            public_host: "127.0.0.1".into(),
            base_api_port: ports.base_api,
            base_p2p_port: ports.base_p2p,
            out_dir: directory.to_path_buf(),
            extra_accounts: 0,
            assets: Vec::new(),
            block_cadence_ms: None,
            consensus_mode: SumeragiConsensusMode::Permissioned,
        },
        publication_root,
    )
    .map_err(|error| Error::Invalid(format!("localnet preparation failed: {error}")))?;
    let directory = directory.canonicalize()?;
    let client_config = directory.join("client.toml");
    let bytes = iroha_fs::read_private(&client_config, 1024 * 1024)?;
    let (config, _) =
        iroha::config::Config::load_bytes_with_musubi_publication(&client_config, &bytes)
            .map_err(|_| Error::Invalid("generated client configuration is invalid".into()))?;
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let published = publication_root.unwrap_or(&directory);
    let context = ManagedContext {
        name: name.into(),
        chain_id: config.chain.to_string(),
        network_id: config.network_id.to_string(),
        account_id: config.account.to_string(),
        torii_url: config.torii_api_url.to_string(),
        client_config: published.join("client.toml"),
        dataspace_alias: "universal".into(),
        dataspace_id: 0,
    };
    let peers = (0..4)
        .map(|index| ManagedPeer {
            config_path: published.join(format!("peer{index}.toml")),
            torii_url: format!("http://127.0.0.1:{}/", ports.base_api + index),
            log_name: format!("peer{index}.log"),
        })
        .collect();
    Ok(PreparedLocalnet {
        context,
        peers,
        service_profile,
    })
}

impl crate::managed::PreparedLocalnet {
    /// Original generation's shared resolver and archive cache for managed contract builds.
    ///
    /// This is path intent only: it performs no reads, creates no directories, and grants no
    /// registry authority. Both global and private roots use the same layout. Managed callers
    /// retain this path from their validated generation before lazy registry discovery.
    #[must_use]
    pub fn build_cache_root(&self) -> PathBuf {
        self.context
            .client_config
            .with_file_name(LOCALNET_RUNTIME_DIRECTORY)
            .join("build-cache")
    }

    /// Load the retained HTTP operator key and verify its binding on every generated validator.
    ///
    /// This credential grants operator-route access and stays separate from the ledger signer
    /// returned by [`crate::managed::ManagedContext::load_client_config`]. Callers keep it in
    /// memory only; no configuration file or secret bytes should be displayed by the frontend.
    ///
    /// # Errors
    /// Rejects changed layout, unsafe custody, malformed keys or inconsistent public bindings.
    pub fn load_operator_key_pair(&self) -> crate::managed::Result<KeyPair> {
        use crate::managed::Error;
        let invalid = || Error::Invalid("managed HTTP operator binding is invalid".into());
        self.context.load_client_config()?;
        if self.peers.len() != 4
            || self.context.client_config.file_name() != Some(std::ffi::OsStr::new("client.toml"))
        {
            return Err(invalid());
        }
        let root = iroha_fs::PrivateDirectory::open(
            self.context.client_config.parent().ok_or_else(invalid)?,
        )?;
        let runtime =
            iroha_fs::PrivateDirectory::open(root.path().join(LOCALNET_RUNTIME_DIRECTORY))?;
        let bytes = runtime.read(LOCALNET_OPERATOR_SIGNER_KEY_FILE, 4096)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        let literal = text.strip_suffix('\n').ok_or_else(invalid)?;
        let key: ExposedPrivateKey = literal.parse().map_err(|_| invalid())?;
        let canonical = Zeroizing::new(key.try_to_multihash_string().map_err(|_| invalid())?);
        if canonical.as_str() != literal {
            return Err(invalid());
        }
        let key = KeyPair::from_private_key(key.0).map_err(|_| invalid())?;
        let expected = key.public_key().to_string();
        for (index, peer) in self.peers.iter().enumerate() {
            if peer.config_path != root.path().join(format!("peer{index}.toml")) {
                return Err(invalid());
            }
            let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
            let table = crate::secret_toml::Table::new(
                crate::secret_toml::parse_table(text, "managed validator")
                    .map_err(|_| invalid())?,
            );
            let operator = table
                .get("torii")
                .and_then(|value| value.get("operator_signatures"))
                .and_then(toml::Value::as_table)
                .ok_or_else(invalid)?;
            let allowed = operator
                .get("allowed_public_keys")
                .and_then(toml::Value::as_array)
                .ok_or_else(invalid)?;
            if operator.get("enabled").and_then(toml::Value::as_bool) != Some(true)
                || allowed.len() != 1
                || allowed[0].as_str() != Some(expected.as_str())
            {
                return Err(invalid());
            }
        }
        Ok(key)
    }
}
