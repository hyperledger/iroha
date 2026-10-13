// Iroha node executable and native runtime bootstrap.
#[cfg(all(feature = "test-network-parliament-signers", not(debug_assertions)))]
compile_error!(
    "the feature-isolated Parliament fixture signers cannot be compiled into an optimized daemon"
);
/// Durable, independently verified native AMX relay delivery.
mod amx_relay;
/// Metadata derived from the authenticated and executed native genesis.
pub mod authenticated_genesis;
/// Per-seat authenticated global-beacon DKG and exact-quorum rotation provisioning.
#[cfg(unix)]
pub mod beacon_bootstrap;
/// Read-only `--check-config --json` and `--check-storage` compatibility probes.
mod compatibility_probe;
/// Iroha server command-line interface and node bootstrap entrypoint.
mod i18n;
/// Deployment-injected factory for the supervised private Musubi publication service.
pub mod musubi_publication_service;
mod network_relay;
/// Fixed-name runtime secrets of a `data_dir` node.
#[cfg(feature = "daemon")]
pub mod node_secrets;
/// Asynchronous Nexus DPN fee settlement relay.
/// Explicit recovery boundaries for daemon-owned provider work.
mod panic_recovery;
/// Synchronizes peer-gossip voter authority with the committed validator roster.
#[path = "main/peers_gossiper_topology_sync.rs"]
mod peers_gossiper_topology_sync;
/// Platform-fixed local runtime-provider broker used by the stock launcher.
mod runtime_provider_broker;
/// Deployment-owned runtime-provider registry boundary for the standard launcher.
pub mod runtime_provider_registry;
/// In-node SCCP keeper with a node-generated keeper key.
#[cfg(unix)]
#[path = "sccp_keeper.rs"]
mod sccp_keeper;
mod sccp_staking_policy;
/// Embedded Soracloud runtime-manager reconciliation.
#[path = "soracloud_runtime.rs"]
mod soracloud_runtime;
/// Exact external signer boundary for Soracloud runtime mutations.
pub mod soracloud_runtime_signer;
/// Stock assembly of the configured production compliance HTTPS transport.
mod sorafs_gateway_compliance_transport;
/// Supervised committed `SoraFS` hedging/billing projector and delivery worker.
pub mod sorafs_hedging_billing_runtime;
/// Explicit owner-only software credentials for the four native transaction roles.
#[cfg(any(unix, windows))]
mod sorafs_native_software_signers;
/// Fail-closed config-bound `SoraFS` `PoP` runtime construction.
pub mod sorafs_pop_runtime;
/// Supervised finalized-PoR reputation reconciliation and optional archive compaction.
pub mod sorafs_por_replay_archive_runtime;
/// Immutable finalized-ledger query adapter for provider ingest.
pub mod sorafs_provider_ingest_finalized_query;
/// Supervised finalized-ledger `SoraFS` provider-ingest worker.
pub mod sorafs_provider_ingest_runtime;
/// Native authenticated remote repair chunk reader.
pub mod sorafs_repair_source;
/// Immutable finalized-ledger query adapter for the reputation runtime.
pub mod sorafs_reputation_finalized_query;
/// Supervised committed `SoraFS` reputation projector and publisher.
pub mod sorafs_reputation_runtime;
/// Supervised finalized reserve-event transparency ingestion.
pub mod sorafs_reserve_transparency_runtime;
/// Qualified stream-token gateway admission and durable callback reconciliation.
mod sorafs_stream_token_gateway_runtime;
/// Bounded local readers for startup trust-root artifacts.
#[path = "main/startup_artifact.rs"]
mod startup_artifact;
/// Native Falcon-backed standalone Taira Bootle/Lantern issuer broker.
#[cfg(feature = "daemon")]
pub mod taira_bootle_lantern_broker;
/// Fixed-descriptor runtime signer and Taira deployment launcher.
#[cfg(unix)]
pub mod taira_runtime_signer;
use crate::soracloud_runtime::{
    QueuedSoracloudRuntimeMutationSink, SoracloudRuntimeManager, SoracloudRuntimeManagerHandle,
};
use clap::{CommandFactory, FromArgMatches, Parser};
use error_stack::{Report, ResultExt};
use eyre::Result as EyreResult;
use fastpq_prover::MetalOverrides;
use iroha_config::{
    base::{WithOrigin, read::ConfigReader, util::Emitter},
    kura::InitMode,
    node_config::{NodeConfigOptions, NodeFile, open_node_config},
    parameters::{
        actual::{
            FastpqExecutionMode, FastpqPoseidonMode, NexusStorageBudgetComponent,
            NexusStorageFilesystemBudget, Root as Config,
        },
        user::Root as UserConfig,
    },
    snapshot::Mode as SnapshotMode,
};
#[cfg(feature = "telemetry")]
use iroha_core::telemetry::{StateTelemetry, StreamingTelemetry};
use iroha_core::{
    IrohaNetwork,
    compliance::LaneComplianceEngine,
    gossiper::{TransactionGossiper, TransactionGossiperHandle},
    governance::manifest::{
        GovernanceGuardError, LaneManifestRegistry, LaneManifestRegistryHandle,
    },
    kiso::{KisoHandle, SoranetHandshakeApplyRequest},
    kura::Kura,
    peers_gossiper::PeersGossiper,
    query::store::LiveQueryStore,
    queue::{ConfigLaneRouter, LaneRouter, Queue},
    smartcontracts::isi::Registrable as _,
    snapshot::{
        SnapshotMaker, TryReadError as TryReadSnapshotError, try_read_snapshot_with_limits,
    },
    state::{State, StateReadOnly as _, World, WorldReadOnly as _},
    streaming::{ManifestPublisher, run_ticket_event_listener},
    sumeragi::filter_validators_from_trusted,
};
#[cfg(test)]
use iroha_core::{block::ValidBlock, sumeragi::network_topology::Topology};
use iroha_crypto::Algorithm;
use iroha_data_model::{
    isi::RegisterPeerWithPop,
    parameter::system::{
        ConsensusHandshakeMetadata, confidential_metadata, consensus_metadata, crypto_metadata,
    },
};
use iroha_data_model::{prelude::*, transaction::Executable};
use iroha_futures::supervisor::{Child, OnShutdown, ShutdownSignal, Supervisor};
use iroha_genesis::{
    GenesisBlock, ManifestCrypto, RawGenesisTransaction, compute_genesis_vk_set_hash,
    init_instruction_registry as init_genesis_instruction_registry,
};
use iroha_logger::actor::LoggerHandle;
use iroha_primitives::addr::SocketAddr;
use iroha_primitives::erasure::rs16;
use iroha_primitives::json::Json;
use iroha_primitives::time::TimeSource;
#[cfg(feature = "telemetry")]
use iroha_telemetry::metrics::set_duplicate_metrics_panic;
use iroha_torii::Torii;
use norito::{codec::Encode, derive::JsonDeserialize, streaming::CapabilityFlags};
use parking_lot::deadlock;
pub use runtime_provider_broker::{
    BootleLanternIssuanceBrokerBackendErrorV1, BootleLanternIssuanceBrokerBackendV1,
    ConsensusSignerProviderQualificationV1, GlobalBeaconPartialSignerBrokerBackendErrorV1,
    GlobalBeaconPartialSignerBrokerBackendV1,
    ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,
    ParliamentTlePartialReleaseSignerBrokerBackendV1, RuntimeProviderBrokerBackendRegistryV1,
    RuntimeProviderBrokerBackendsV1, RuntimeProviderBrokerDeploymentV1,
    RuntimeProviderBrokerExecutableArgsV1, RuntimeProviderBrokerExecutableErrorV1,
    RuntimeProviderBrokerExecutableV1, RuntimeProviderBrokerLauncherErrorV1,
    RuntimeProviderBrokerLifecycleV1, RuntimeProviderBrokerReadinessErrorV1,
    RuntimeProviderBrokerServerErrorV1, StockGovernanceDagServiceRuntimeProviderRegistryV1,
    load_runtime_provider_broker_catalog_file_v1, load_runtime_provider_broker_policy_file_v1,
    serve_runtime_provider_broker_v1, serve_runtime_provider_broker_with_fallible_readiness_v1,
    serve_runtime_provider_broker_with_lifecycle_v1,
};
#[cfg(all(
    feature = "test-network-disposable-broker",
    any(target_os = "linux", target_os = "macos")
))]
pub use runtime_provider_broker::{
    load_owner_private_runtime_provider_broker_catalog_file_v1,
    load_owner_private_runtime_provider_broker_policy_file_v1,
};
pub use runtime_provider_registry::{
    IrohaRuntimeProviderBindingV1, IrohaRuntimeProviderBindingsV1,
    IrohaRuntimeProviderCatalogErrorV1, IrohaRuntimeProviderRegistryErrorV1,
    IrohaRuntimeProviderRegistryV1, IrohaRuntimeProviderSlotV1,
    RUNTIME_PROVIDER_CATALOG_MAX_BYTES_V1,
};
#[cfg(test)]
use startup_artifact::read_genesis_unlocked;
use startup_artifact::{
    INTEGRITY_BOUND_CONFIG_MAX_BYTES_V1, read_bounded_startup_artifact, read_genesis_manifest,
    read_genesis_unlocked_with_bytes,
};
#[cfg(target_os = "windows")]
use std::os::windows::{ffi::OsStrExt, fs::MetadataExt as _};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    env,
    ffi::OsString,
    fs,
    future::Future,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::broadcast, task};

const NODE_RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// Build-time source identity embedded for release artifact validation.
use iroha_core::release_identity::CompiledBuildMetadata;
/// Emit a startup-stage timing at debug level; the configured logger level controls it.
fn log_startup_trace(stage: &'static str, started_at: Instant) {
    iroha_logger::debug!(
        stage,
        elapsed_ms = started_at.elapsed().as_millis(),
        "startup trace"
    );
}
fn torii_receipt_signer_or_derived(
    receipt_signer: Option<KeyPair>,
    node_key_pair: &KeyPair,
) -> Result<KeyPair, iroha_crypto::Error> {
    if let Some(receipt_signer) = receipt_signer {
        return Ok(receipt_signer);
    }
    // A receipt key must survive process restarts because the durable DA log verifies historical
    // receipts during startup. Derive a separate key from the node identity instead of generating
    // an ephemeral key; the BLAKE3 KDF context prevents reuse as the node key or by another protocol.
    let (node_algorithm, mut node_secret) = node_key_pair.private_key().try_to_bytes()?;
    let mut key_deriver = blake3::Hasher::new_derive_key("iroha:torii:receipt-signer:secp256k1:v1");
    key_deriver.update(node_algorithm.as_static_str().as_bytes());
    key_deriver.update(&[0]);
    key_deriver.update(&node_secret);
    let mut seed = [0_u8; 32];
    key_deriver.finalize_xof().fill(&mut seed);
    node_secret.fill(0);
    let key = iroha_crypto::KeyPair::try_from_seed(seed.to_vec(), Algorithm::Secp256k1);
    seed.fill(0);
    let key = key?;
    let algorithm = key
        .public_key()
        .try_algorithm()
        .map_or("malformed", |algorithm| algorithm.as_static_str());
    iroha_logger::info!(
        algorithm,
        "torii receipt signer not configured; derived a stable domain-separated key from the node identity"
    );
    Ok(key)
}
type ConsensusHandshakeMeta = ConsensusHandshakeMetadata;
fn parse_handshake_meta_str(raw: &str) -> Result<ConsensusHandshakeMeta, norito::Error> {
    let metadata: ConsensusHandshakeMeta =
        norito::json::from_str(raw).map_err(norito::Error::from)?;
    metadata
        .validate()
        .map_err(|error| norito::Error::Message(error.clone()))?;
    Ok(metadata)
}
fn parse_manifest_crypto_str(raw: &str) -> Result<ManifestCrypto, norito::Error> {
    norito::json::from_str(raw).map_err(norito::Error::from)
}
fn parse_confidential_registry_meta_str(
    raw: &str,
) -> Result<ConfidentialRegistryMeta, norito::Error> {
    norito::json::from_str(raw).map_err(norito::Error::from)
}
fn decode_crypto_manifest_meta(payload: &Json) -> Result<ManifestCrypto, norito::Error> {
    match parse_manifest_crypto_str(payload.get()) {
        Ok(meta) => Ok(meta),
        Err(error) => {
            let preview: String = payload.get().chars().take(256).collect();
            tracing::warn!(?error, preview = %preview, "failed to decode crypto_manifest_meta payload");
            Err(norito::Error::Message(
                "failed to decode crypto_manifest_meta payload".to_string(),
            ))
        }
    }
}
fn decode_confidential_registry_meta(
    payload: &Json,
) -> Result<ConfidentialRegistryMeta, norito::Error> {
    parse_confidential_registry_meta_str(payload.get()).map_err(|_| {
        norito::Error::Message("failed to decode confidential_registry_root payload".to_string())
    })
}
/// The confidential feature digest this node advertises in the P2P handshake.
///
/// It binds the confidential rules version and the protocol-default ZK and SCCP
/// policy hash of the release. It reads no State: the committed
/// `zk_validity_policy_v1` of a chain is decided by its blocks, and a value
/// that differs between peers at different heights cannot gate a connection.
fn handshake_confidential_features() -> iroha_data_model::confidential::ConfidentialFeatureDigest {
    iroha_data_model::confidential::ConfidentialFeatureDigest::new(
        None,
        None,
        None,
        Some(iroha_config::parameters::defaults::confidential::RULES_VERSION),
        Some(iroha_core::state::default_genesis_confidential_policy_hash()),
    )
}
fn confidential_handshake_policy_digest(
    digest: iroha_data_model::confidential::ConfidentialFeatureDigest,
) -> iroha_data_model::confidential::ConfidentialFeatureDigest {
    iroha_data_model::confidential::ConfidentialFeatureDigest::new(
        None,
        None,
        None,
        digest.conf_rules_version,
        Some(iroha_core::state::default_genesis_confidential_policy_hash()),
    )
}
fn decode_consensus_handshake_meta(
    payload: &Json,
) -> Result<ConsensusHandshakeMeta, norito::Error> {
    parse_handshake_meta_str(payload.get()).map_err(|_| {
        norito::Error::Message("failed to decode consensus_handshake_meta payload".to_string())
    })
}
type SharedSoraFsProviderCache = Arc<tokio::sync::RwLock<iroha_torii::sorafs::ProviderAdvertCache>>;
#[derive(Debug)]
enum SharedSoraFsProviderCacheError {
    UnknownCapability(String),
    DuplicateCapability(String),
    EmptyCapabilities,
    ReplayCheckpoint {
        path: PathBuf,
        source: iroha_torii::sorafs::ReplayCheckpointError,
    },
}
impl core::fmt::Display for SharedSoraFsProviderCacheError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownCapability(name) => write!(
                formatter,
                "unknown SoraFS capability `{name}` in torii.sorafs.known_capabilities"
            ),
            Self::DuplicateCapability(name) => write!(
                formatter,
                "duplicate SoraFS capability `{name}` in torii.sorafs.known_capabilities"
            ),
            Self::EmptyCapabilities => formatter
                .write_str("torii.sorafs.known_capabilities must include at least one capability"),
            Self::ReplayCheckpoint { path, source } => write!(
                formatter,
                "failed to load SoraFS provider replay checkpoint {}: {source}",
                path.display()
            ),
        }
    }
}
impl std::error::Error for SharedSoraFsProviderCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReplayCheckpoint { source, .. } => Some(source),
            Self::UnknownCapability(_) | Self::DuplicateCapability(_) | Self::EmptyCapabilities => {
                None
            }
        }
    }
}
fn build_shared_sorafs_provider_cache(
    config: &Config,
    state: Arc<State>,
) -> Result<Option<SharedSoraFsProviderCache>, SharedSoraFsProviderCacheError> {
    let discovery = &config.torii.sorafs_discovery;
    if !discovery.discovery_enabled {
        return Ok(None);
    }
    let mut capabilities = Vec::new();
    for name in &discovery.known_capabilities {
        let capability = iroha_torii::sorafs::parse_capability_name(name)
            .ok_or_else(|| SharedSoraFsProviderCacheError::UnknownCapability(name.clone()))?;
        if capabilities.contains(&capability) {
            return Err(SharedSoraFsProviderCacheError::DuplicateCapability(
                name.clone(),
            ));
        }
        capabilities.push(capability);
    }
    if capabilities.is_empty() {
        return Err(SharedSoraFsProviderCacheError::EmptyCapabilities);
    }
    let admission = Arc::new(iroha_torii::sorafs::AdmissionRegistry::from_state(state));
    let replay_checkpoint_path = if discovery.replay_checkpoint_path.is_absolute() {
        discovery.replay_checkpoint_path.clone()
    } else {
        config
            .torii
            .data_dir
            .join(&discovery.replay_checkpoint_path)
    };
    let cache = iroha_torii::sorafs::ProviderAdvertCache::new_persistent(
        capabilities,
        admission,
        replay_checkpoint_path.clone(),
        discovery.replay_checkpoint_max_entries,
    )
    .map_err(|source| SharedSoraFsProviderCacheError::ReplayCheckpoint {
        path: replay_checkpoint_path,
        source,
    })?;
    Ok(Some(Arc::new(tokio::sync::RwLock::new(cache))))
}
include!("main/shared_sorafs_provider_cache_tests.rs");
#[cfg(test)]
fn deterministic_test_genesis_topology() -> Vec<iroha_genesis::GenesisTopologyEntry> {
    (0_u8..4)
        .map(|index| {
            let key_pair = iroha_crypto::KeyPair::try_from_seed(
                vec![0x40_u8.wrapping_add(index); 32],
                Algorithm::BlsNormal,
            )
            .expect("derive deterministic test genesis validator");
            let pop = iroha_crypto::bls_normal_pop_prove(key_pair.private_key())
                .expect("derive deterministic test genesis validator proof of possession");
            iroha_genesis::GenesisTopologyEntry::new(
                PeerId::new(key_pair.public_key().clone()),
                pop,
            )
        })
        .collect()
}

#[cfg(test)]
fn complete_test_genesis_builder_for_topology(
    builder: iroha_genesis::GenesisBuilder,
    mut topology: Vec<iroha_genesis::GenesisTopologyEntry>,
) -> iroha_genesis::GenesisBuilder {
    topology.sort_by(|left, right| left.peer.cmp(&right.peer));
    assert!(
        iroha_data_model::block::consensus::is_valid_committee_size(topology.len()),
        "irohad genesis fixtures require an exact supported 3f + 1 topology"
    );
    assert!(
        !topology.windows(2).any(|pair| pair[0].peer == pair[1].peer),
        "irohad genesis fixture topology must not repeat validators"
    );
    for entry in &topology {
        let pop = entry
            .pop_bytes()
            .expect("decode irohad test validator proof of possession")
            .expect("irohad test validator must carry a proof of possession");
        iroha_crypto::bls_normal_pop_verify(entry.peer.public_key(), &pop)
            .expect("verify irohad test validator proof of possession");
    }
    builder
        .set_topology(topology)
        .with_sumeragi_context_parameters(
            iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
        )
}

#[cfg(test)]
fn complete_test_genesis_builder(
    builder: iroha_genesis::GenesisBuilder,
) -> iroha_genesis::GenesisBuilder {
    complete_test_genesis_builder_for_topology(builder, deterministic_test_genesis_topology())
}

#[cfg(test)]
mod handshake_payload_tests {
    use super::*;
    use iroha_genesis::{GenesisBuilder, ManifestCrypto};
    use std::path::PathBuf;
    fn handshake_payload_from_genesis() -> Json {
        let chain = iroha_model_base::chain::ChainId::from("handshake-meta-test");
        let manifest = complete_test_genesis_builder(GenesisBuilder::new_without_executor(
            chain,
            PathBuf::from("."),
        ))
        .build_raw()
        .expect("build complete handshake metadata test genesis")
        .with_consensus_meta()
        .expect("valid fixture consensus parameters");
        let keypair = iroha_crypto::KeyPair::random();
        let genesis_block = manifest
            .build_and_sign(&keypair)
            .expect("sign genesis with meta");
        for tx in genesis_block.0.external_transactions() {
            if let Executable::Instructions(batch) = tx.instructions() {
                for instr in batch {
                    if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
                        && let Parameter::Custom(custom) = set_param.inner()
                        && custom.id() == &consensus_metadata::handshake_meta_id()
                    {
                        return custom.payload().clone();
                    }
                }
            }
        }
        panic!("handshake payload not found");
    }
    #[test]
    fn decode_consensus_meta_rejects_nested_json_string_payload() {
        let payload = handshake_payload_from_genesis();
        let meta = decode_consensus_handshake_meta(&payload).expect("decode normal payload");
        assert_eq!(
            meta.mode,
            iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned
        );
        let stringified =
            Json::new(norito::json::to_json(&payload).expect("stringify handshake payload"));
        let err =
            decode_consensus_handshake_meta(&stringified).expect_err("nested payload must fail");
        assert!(
            err.to_string().contains("failed to decode"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn decode_consensus_meta_rejects_garbage() {
        let bad = Json::from_norito_value_ref(&norito::json::Value::String("not json".into()))
            .expect("construct bad json");
        let err = decode_consensus_handshake_meta(&bad).expect_err("garbage must fail");
        assert!(
            err.to_string().contains("failed to decode"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn decode_consensus_meta_rejects_mangled_json() {
        let mangled = Json::from_norito_value_ref(&norito::json::Value::String(
            r#"{mode"Permissioned",bls_domain"bls-iroha3:permissioned-sumeragi:v1",consensus_fingerprint"0x632eaff6fe3054ca279416357baae5ff7f28144b3bc6a83921f68d466c4ec0ab"}"#.to_string(),
        ))
        .expect("construct mangled payload");
        let err = decode_consensus_handshake_meta(&mangled).expect_err("mangled payload must fail");
        assert!(
            err.to_string().contains("failed to decode"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn decode_consensus_meta_rejects_unprefixed_hex_and_uppercase_tokens() {
        let fingerprint = "632eaff6fe3054ca279416357baae5ff7f28144b3bc6a83921f68d466c4ec0ab";
        let raw = format!(
            "MODE=PERMISSIONED bls_domain=bls-iroha3:permissioned-sumeragi:v1 consensus_fingerprint={fingerprint}"
        );
        let payload = Json::from(raw.as_str());
        let err =
            decode_consensus_handshake_meta(&payload).expect_err("non-JSON payload must fail");
        assert!(
            err.to_string().contains("failed to decode"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn decode_crypto_manifest_meta_rejects_nested_json_string_payload() {
        let manifest = ManifestCrypto::default();
        let payload = Json::new(manifest.clone());
        let decoded = decode_crypto_manifest_meta(&payload).expect("decode normal payload");
        assert_eq!(decoded, manifest);
        let stringified =
            Json::new(norito::json::to_json(&payload).expect("stringify manifest payload"));
        let err = decode_crypto_manifest_meta(&stringified)
            .expect_err("nested string payload must be rejected");
        assert!(
            err.to_string().contains("failed to decode"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn decode_crypto_manifest_meta_rejects_raw_quoted_legacy_payload() {
        let raw = r#""{"allowed_curve_ids":[1,3,4],"allowed_signing":["ed25519","secp256k1","bls_normal"],"default_hash":"blake2b-256","sm2_distid_default":"1234567812345678","sm_openssl_preview":false}""#;
        assert!(
            Json::from_raw_json(raw.to_owned()).is_err(),
            "raw-quoted compatibility payload must be rejected at construction"
        );
    }
    #[test]
    fn decode_crypto_manifest_meta_rejects_backslash_escaped_object_payload() {
        let raw = r#"{\"allowed_curve_ids\":[1,3,4],\"allowed_signing\":[\"ed25519\",\"secp256k1\",\"bls_normal\"],\"default_hash\":\"blake2b-256\",\"sm2_distid_default\":\"1234567812345678\",\"sm_openssl_preview\":false}"#;
        assert!(
            Json::from_raw_json(raw.to_owned()).is_err(),
            "backslash-escaped compatibility payload must be rejected at construction"
        );
    }
    #[test]
    fn decode_crypto_manifest_meta_rejects_mangled_key_value_separators() {
        let raw = r#"{"allowed_curve_ids""[1,3,4],"allowed_signing""["ed25519","secp256k1","bls_normal"],"default_hash""blake2b-256","sm2_distid_default""1234567812345678","sm_openssl_preview"false}"#;
        assert!(
            Json::from_raw_json(raw.to_owned()).is_err(),
            "mangled compatibility payload must be rejected at construction"
        );
    }
    #[test]
    fn decode_confidential_registry_meta_handles_normal_json() {
        let hash = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let payload = Json::from_raw_json(format!("{{\"vk_set_hash\":\"{hash}\"}}"))
            .expect("valid confidential registry JSON");
        let decoded =
            decode_confidential_registry_meta(&payload).expect("decode confidential payload");
        assert_eq!(decoded.vk_set_hash.as_deref(), Some(hash));
    }
    #[test]
    fn decode_confidential_registry_meta_rejects_mangled_key_value_separators() {
        let hash = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(
            Json::from_raw_json(format!("{{\"vk_set_hash\"\"{hash}\"}}")).is_err(),
            "mangled compatibility payload must fail at construction"
        );
    }
    #[test]
    fn parse_confidential_registry_hash_treats_json_null_as_absent() {
        let payload = Json::from_raw_json("{\"vk_set_hash\":null}".to_string())
            .expect("valid null confidential registry JSON");
        let decoded =
            parse_confidential_registry_hash(&payload).expect("decode null confidential payload");
        assert_eq!(decoded, None);
    }
    #[test]
    fn handshake_confidential_features_identify_the_release_not_committed_state() {
        // The advertised digest is the protocol default whatever a chain commits:
        // a node that restarts after an authorized policy change advertises the
        // same value as its peers that did not restart.
        let features = handshake_confidential_features();
        assert_eq!(
            features.zk_policy_hash,
            Some(iroha_core::state::default_genesis_confidential_policy_hash())
        );
        assert_eq!(
            features.conf_rules_version,
            Some(iroha_config::parameters::defaults::confidential::RULES_VERSION)
        );
        assert_eq!(confidential_handshake_policy_digest(features), features);
        // A State that holds a committed policy reports another policy hash to
        // consensus, and the handshake value does not follow it.
        let mut policy = iroha_core::zk_validity_policy::ZkValidityPolicyV1::protocol_default();
        policy.confidential.max_nullifiers_per_tx += 1;
        let world = iroha_core::state::World::default();
        {
            let mut block = world.block();
            block
                .parameters
                .get_mut()
                .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                    policy.into_custom_parameter(),
                ))
                .expect("install the committed pipeline fixture policy");
            block.commit();
        }
        let state = iroha_core::state::State::new_for_testing(
            world,
            iroha_core::kura::Kura::blank_kura_for_testing(),
            iroha_core::query::store::LiveQueryStore::start_test(),
        );
        let committed = iroha_core::state::combine_zk_and_sccp_policy_hashes(
            iroha_core::state::compute_zk_consensus_policy_hash(&state.zk_snapshot()),
            iroha_core::state::sccp_genesis_policy_hash_v1(),
        );
        assert_ne!(Some(committed), features.zk_policy_hash);
        assert_eq!(handshake_confidential_features(), features);
    }
    #[test]
    fn confidential_handshake_digest_excludes_height_dependent_registry_fields() {
        let digest = iroha_data_model::confidential::ConfidentialFeatureDigest::new(
            Some([1; 32]),
            Some(7),
            Some(9),
            Some(1),
            Some([2; 32]),
        );
        let handshake = confidential_handshake_policy_digest(digest);
        assert_eq!(handshake.vk_set_hash, None);
        assert_eq!(handshake.poseidon_params_id, None);
        assert_eq!(handshake.pedersen_params_id, None);
        assert_eq!(handshake.conf_rules_version, Some(1));
        // The block digest's policy hash binds the light-client profile versions active at its
        // height; the handshake binds the version-1 profiles, so a Parliament profile
        // activation never splits peers at different heights.
        assert_eq!(
            handshake.zk_policy_hash,
            Some(iroha_core::state::default_genesis_confidential_policy_hash())
        );
        let after_activation = iroha_data_model::confidential::ConfidentialFeatureDigest {
            zk_policy_hash: Some([3; 32]),
            ..digest
        };
        assert_eq!(
            confidential_handshake_policy_digest(after_activation),
            handshake
        );
    }
}
#[derive(Debug, JsonDeserialize)]
struct ConfidentialRegistryMeta {
    #[norito(default)]
    vk_set_hash: Option<String>,
}
#[cfg(feature = "beep")]
use ivm::IVM;
use ivm::set_banner_enabled;
/// Detect if the current terminal supports ANSI colors.
pub fn is_coloring_supported() -> bool {
    supports_color::on(supports_color::Stream::Stdout).is_some()
}
fn default_terminal_colors_str() -> clap::builder::OsStr {
    is_coloring_supported().to_string().into()
}
#[cfg(feature = "telemetry")]
fn init_global_metrics_handle(
    panic_on_duplicate_metrics: bool,
) -> Arc<iroha_telemetry::metrics::Metrics> {
    set_duplicate_metrics_panic(panic_on_duplicate_metrics);
    iroha_telemetry::metrics::global().map_or_else(
        || {
            let metrics = Arc::new(iroha_telemetry::metrics::Metrics::default());
            match iroha_telemetry::metrics::install_global(Arc::clone(&metrics)) {
                Ok(()) => metrics,
                Err(_) => iroha_telemetry::metrics::global_or_default(),
            }
        },
        Arc::clone,
    )
}
fn nexus_topology_is_custom(nexus: &iroha_config::parameters::actual::Nexus) -> bool {
    nexus.uses_multilane_catalogs()
}
mod startup_root_topology;
fn ensure_manifest_crypto_matches(
    manifest: &RawGenesisTransaction,
    config: &Config,
) -> Result<(), String> {
    ensure_crypto_snapshot_matches_config(manifest.crypto(), config)
}
fn ensure_crypto_snapshot_matches_config(
    manifest_crypto: &ManifestCrypto,
    config: &Config,
) -> Result<(), String> {
    manifest_crypto
        .validate()
        .map_err(|err| format!("Invalid crypto section in genesis manifest: {err:?}"))?;
    let mut manifest_allowed = manifest_crypto.allowed_signing.clone();
    manifest_allowed.sort();
    manifest_allowed.dedup();
    let mut config_allowed = config.crypto.allowed_signing.clone();
    config_allowed.sort();
    config_allowed.dedup();
    let hashes_match = manifest_crypto
        .default_hash
        .eq_ignore_ascii_case(&config.crypto.default_hash);
    let distid_match = manifest_crypto.sm2_distid_default == config.crypto.sm2_distid_default;
    let manifest_sm_helpers = manifest_crypto
        .allowed_signing
        .iter()
        .any(|algo| algo.as_static_str().eq_ignore_ascii_case("sm2"));
    let config_sm_helpers = config.crypto.sm_helpers_enabled();
    let preview_match =
        manifest_crypto.sm_openssl_preview == config.crypto.enable_sm_openssl_preview;
    let mut manifest_curves =
        iroha_config::parameters::actual::Crypto::from(manifest_crypto.clone()).allowed_curve_ids;
    manifest_curves.sort_unstable();
    manifest_curves.dedup();
    let mut config_curves = config.crypto.allowed_curve_ids.clone();
    config_curves.sort_unstable();
    config_curves.dedup();
    if !hashes_match
        || manifest_allowed != config_allowed
        || !distid_match
        || manifest_sm_helpers != config_sm_helpers
        || !preview_match
        || manifest_curves != config_curves
    {
        return Err(format!(
            "Genesis manifest crypto mismatch: manifest {{ sm_helpers_enabled: {}, sm_openssl_preview: {}, default_hash: {}, allowed_signing: {:?}, allowed_curve_ids: {:?}, sm2_distid_default: {} }} != config {{ sm_helpers_enabled: {}, sm_openssl_preview: {}, default_hash: {}, allowed_signing: {:?}, allowed_curve_ids: {:?}, sm2_distid_default: {} }}",
            manifest_sm_helpers,
            manifest_crypto.sm_openssl_preview,
            manifest_crypto.default_hash,
            manifest_allowed,
            manifest_curves,
            manifest_crypto.sm2_distid_default,
            config_sm_helpers,
            config.crypto.enable_sm_openssl_preview,
            config.crypto.default_hash,
            config_allowed,
            config_curves,
            config.crypto.sm2_distid_default,
        ));
    }
    Ok(())
}
/// Ensure operator signature policy includes the node identity when requested by config.
fn ensure_operator_node_key_allowlisted(config: &mut Config) {
    if !config.torii.operator_signatures.allow_node_key {
        return;
    }
    let node_public_key = config.common.key_pair.public_key().clone();
    if config
        .torii
        .operator_signatures
        .allowed_public_keys
        .iter()
        .all(|key| key != &node_public_key)
    {
        config
            .torii
            .operator_signatures
            .allowed_public_keys
            .push(node_public_key);
    }
}
#[cfg(feature = "beep")]
fn startup_beep(enable_beep: bool) -> bool {
    if !enable_beep {
        return false;
    }
    IVM::beep_music();
    const SHA256_ABC_EXPECTED: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let _ = SHA256_ABC_EXPECTED;
    true
}
/// Iroha server CLI
#[derive(clap::Args, Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent command-line switch"
)]
pub struct StartupArgs {
    /// Validate configuration and available genesis, then exit without binding network sockets.
    ///
    /// The runtime-only secrets under `<data_dir>/secrets/` (runtime signer and beacon
    /// credential) are never opened; the key files the configuration names are read by
    /// the parser after their custody checks.
    #[arg(long)]
    pub check_config: bool,
    /// With `--check-config`, print this build's and configuration's compatibility values as one
    /// Norito JSON object instead of the `Ready`/`Pending` line.
    #[arg(long, requires = "check_config")]
    pub json: bool,
    /// Inspect the stopped node's Kura store and newest snapshot read-only with this build's
    /// decoders, print the result as one Norito JSON object and exit nonzero on failure.
    ///
    /// Takes the Kura store-root lock, so it refuses a store a running node owns. It never
    /// mutates the store and never opens runtime-only secrets (the configuration is parsed as for
    /// `--check-config`).
    #[arg(long, conflicts_with = "check_config")]
    pub check_storage: bool,
    /// Require this registered account to retain SoraCloud deployment authority
    /// after executing the exact signed genesis during offline validation.
    #[arg(long, value_name = "ACCOUNT_ID", requires = "check_config")]
    pub require_genesis_inrou_deployment_authority: Option<String>,
    /// Enables trace logs of configuration reading & parsing.
    ///
    /// Might be useful for configuration troubleshooting.
    #[arg(long, env)]
    pub trace_config: bool,
    /// Require the configuration file bytes to match this lowercase or uppercase
    /// 64-digit BLAKE3 digest.
    ///
    /// Integrity-bound files are parsed from the exact bytes that were hashed
    /// and must be flattened (the `extends` directive is not accepted).
    #[arg(long, value_name = "HEX", requires = "config")]
    pub config_blake3: Option<String>,
    /// Assert, at this boot only, that the node's consensus keys never signed for this chain.
    ///
    /// Sumeragi keeps a safety record per key; without one it signs nothing until it has proof
    /// that its record was not lost. Pass this once, at the first boot of a new key, and never
    /// after a data loss.
    #[arg(long)]
    pub sumeragi_assert_fresh_key: bool,
}

#[cfg(feature = "test-network-parliament-signers")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
enum TestNetworkParliamentBeaconSignerMode {
    #[default]
    Valid,
    Absent,
    Invalid,
}

/// Complete command-line arguments for the Iroha server.
#[derive(Parser, Debug)]
#[command(
    name = "iroha3d",
    version = env!("CARGO_PKG_VERSION"),
    author
)]
pub struct Args {
    /// Path to the configuration file
    #[arg(long, short, value_name("PATH"), value_hint(clap::ValueHint::FilePath))]
    pub config: Option<PathBuf>,
    /// Optional path to genesis manifest JSON for consensus validation
    #[arg(long, value_name = "PATH", value_hint(clap::ValueHint::FilePath))]
    pub genesis_manifest_json: Option<PathBuf>,
    /// Startup and configuration-validation switches.
    #[command(flatten)]
    pub startup: StartupArgs,
    /// Whether to enable ANSI-colored output or not
    ///
    /// By default, Iroha determines whether the terminal supports colors or not.
    ///
    /// In order to disable this flag explicitly, pass `--terminal-colors=false`.
    #[arg(
        long,
        env,
        default_missing_value("true"),
        default_value(default_terminal_colors_str()),
        action(clap::ArgAction::Set),
        require_equals(true),
        num_args(0..=1),
    )]
    pub terminal_colors: bool,
    /// Override system language for messages
    #[arg(long)]
    pub language: Option<String>,
    /// Enable Sora Nexus feature profile (`SoraFS`, `SoraNet` handshake, multi-lane consensus)
    /// while preserving explicitly configured Nexus topology, including default-valued catalogs.
    #[arg(long, env = "IROHA_SORA_PROFILE")]
    pub sora: bool,
    #[cfg(feature = "test-network-parliament-signers")]
    #[arg(
        long = "test-network-parliament-beacon-signer-mode",
        value_enum,
        default_value_t,
        hide = true
    )]
    test_network_parliament_beacon_signer_mode: TestNetworkParliamentBeaconSignerMode,
    /// Override FASTPQ prover execution mode (`cpu` or `gpu`).
    #[arg(
        long = "fastpq-execution-mode",
        value_name = "MODE",
        value_parser = parse_fastpq_execution_mode
    )]
    pub fastpq_execution_mode: Option<FastpqExecutionMode>,
    /// Override the FASTPQ Poseidon pipeline mode (`cpu` or `gpu`).
    #[arg(
        long = "fastpq-poseidon-mode",
        value_name = "MODE",
        value_parser = parse_fastpq_poseidon_mode
    )]
    pub fastpq_poseidon_mode: Option<FastpqPoseidonMode>,
    /// Override the FASTPQ telemetry device-class label (e.g., `apple-m4`, `xeon-rtx-sm80`).
    #[arg(long = "fastpq-device-class", value_name = "LABEL")]
    pub fastpq_device_class: Option<String>,
    /// Override the FASTPQ chip-family label (e.g., `m4`, `xeon-icelake`).
    #[arg(long = "fastpq-chip-family", value_name = "LABEL")]
    pub fastpq_chip_family: Option<String>,
    /// Override the FASTPQ GPU-kind label (e.g., `integrated`, `discrete`).
    #[arg(long = "fastpq-gpu-kind", value_name = "LABEL")]
    pub fastpq_gpu_kind: Option<String>,
}
/// Top-level standard-launcher failure category.
#[derive(Clone, Copy, Debug)]
pub enum MainError {
    /// Configuration tracing could not be initialized.
    TraceConfigSetup,
    /// Static configuration, genesis, or runtime-provider resolution failed.
    Config,
    /// Global logging could not be initialized.
    Logger,
    /// One or more node subsystems failed during startup.
    IrohaStart,
    /// A supervised node subsystem failed while the daemon was running.
    IrohaRun,
    /// `--check-storage` could not read the store or its snapshot restore dry run failed.
    CheckStorage,
}
/// Read-only Torii adapter that refuses committed reputation reads whenever
/// the supervised daemon is not ready.
#[derive(Debug, Clone)]
struct ReadyReputationCommittedReaderV1 {
    runtime: sorafs_reputation_runtime::ReputationRuntimeHandleV1,
}
impl ReadyReputationCommittedReaderV1 {
    fn ensure_ready(&self) -> Result<(), sorafs_node::reputation::runtime::ReputationRuntimeError> {
        if self.runtime.status()?.ready {
            return Ok(());
        }
        let failure =
            sorafs_node::reputation::runtime::ReputationExternalFailureV1::try_new([0x52; 32])?;
        Err(sorafs_node::reputation::runtime::ReputationRuntimeError::External(failure))
    }
}
impl sorafs_node::reputation::runtime::ReputationCommittedReadApiV1
    for ReadyReputationCommittedReaderV1
{
    fn committed_read_projection(
        &self,
    ) -> Result<
        sorafs_node::reputation::runtime::ReputationCommittedReadProjectionV1,
        sorafs_node::reputation::runtime::ReputationRuntimeError,
    > {
        self.ensure_ready()?;
        self.runtime.committed_read_projection()
    }
    fn committed_snapshot_by_id(
        &self,
        snapshot_id: [u8; 16],
    ) -> Result<
        Option<sorafs_manifest::ReputationSnapshotV1>,
        sorafs_node::reputation::runtime::ReputationRuntimeError,
    > {
        self.ensure_ready()?;
        self.runtime.committed_snapshot_by_id(snapshot_id)
    }
    fn committed_events_after(
        &self,
        sequence: u64,
    ) -> Result<
        Vec<sorafs_manifest::ReputationSnapshotEventV1>,
        sorafs_node::reputation::runtime::ReputationRuntimeError,
    > {
        self.ensure_ready()?;
        self.runtime.committed_events_after(sequence)
    }
}
/// [Orchestrator](https://en.wikipedia.org/wiki/Orchestration_%28computing%29)
/// of the system. It configures, coordinates and manages transactions
/// and queries processing, work of consensus and storage.
pub struct Iroha {
    /// Kura — block storage
    kura: Arc<Kura>,
    /// State of blockchain
    state: Arc<State>,
    /// Embedded Soracloud runtime-manager handle.
    soracloud_runtime: Option<SoracloudRuntimeManagerHandle>,
    /// Streaming session manager
    streaming: iroha_core::streaming::StreamingHandle,
    /// P2P network handle used for outbound control frames (e.g., streaming manifests).
    network: IrohaNetwork,
    /// Supervised committed reputation runtime status/metrics handle.
    sorafs_reputation_runtime: Option<sorafs_reputation_runtime::ReputationRuntimeHandleV1>,
    /// Supervised committed hedging/billing runtime status/metrics handle.
    sorafs_hedging_billing_runtime:
        Option<sorafs_hedging_billing_runtime::HedgingBillingRuntimeHandleV1>,
    /// Supervised finalized-ledger provider-ingest status/metrics handle.
    sorafs_provider_ingest_runtime:
        Option<sorafs_provider_ingest_runtime::ProviderIngestRuntimeHandleV1>,
    /// Daemon-owned archive-only provider-ingest finalized query.
    sorafs_provider_ingest_finalized_query: Option<
        Arc<sorafs_provider_ingest_finalized_query::ArchivedProviderIngestFinalizedLedgerV1>,
    >,
    /// Inert take-once tenure joining the exact prepared signed capture reader
    /// to the embedded `SoraFS` storage/outbox incarnation.
    #[allow(dead_code)]
    sorafs_provider_ingest_completed_musubi_capture:
        Option<sorafs_node::ProviderIngestCompletedMusubiCaptureCoordinatorV1>,
}
include!("main/runtime_deps.rs");
/// Error(s) that might occur while starting [`Iroha`]
#[derive(Debug, Copy, Clone)]
pub enum StartError {
    /// Invalid or contradictory executable build metadata.
    BuildIdentity,
    /// Failed to start the P2P network layer
    StartP2p,
    /// Failed to initialize block storage (Kura)
    InitKura,
    /// Failed to listen for OS shutdown signals
    ListenOsSignal,
    /// Failed to start the Torii API server
    StartTorii,
    /// Explicit AMX relay route, custody or journal initialization failed.
    StartAmxRelay,
}
impl std::fmt::Display for MainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = match self {
            MainError::TraceConfigSetup => "error.trace_config_setup",
            MainError::Config => "error.config",
            MainError::Logger => "error.logger",
            MainError::IrohaStart => "error.start",
            MainError::IrohaRun => "error.run",
            MainError::CheckStorage => "error.check_storage",
        };
        write!(f, "{}", i18n::t(key))
    }
}
impl std::error::Error for MainError {}
impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = match self {
            StartError::BuildIdentity => return f.write_str("invalid executable build identity"),
            StartError::StartP2p => "error.start_p2p",
            StartError::InitKura => "error.init_kura",
            StartError::ListenOsSignal => "error.listen_os_signal",
            StartError::StartTorii => "error.start_torii",
            StartError::StartAmxRelay => {
                return f.write_str("failed to initialize native AMX relay");
            }
        };
        write!(f, "{}", i18n::t(key))
    }
}
impl std::error::Error for StartError {}
fn snapshot_mode_allows_restore(mode: SnapshotMode) -> bool {
    !matches!(mode, SnapshotMode::Disabled)
}
fn snapshot_failure_allows_empty_state_fallback(
    error: &TryReadSnapshotError,
    emergency_fast: bool,
) -> bool {
    !emergency_fast && snapshot_read_error_is_recoverable(error)
}
mod snapshot_restore_policy;
use snapshot_restore_policy::snapshot_read_error_is_recoverable;

fn refresh_block_count_after_snapshot_load(
    block_count: &mut iroha_core::kura::BlockCount,
    committed_height: usize,
    kura: &Kura,
) -> Result<(), String> {
    let durable_height = kura
        .exact_durable_blocks_count()
        .map_err(|error| format!("failed to read exact post-snapshot Kura height: {error}"))?;
    let logical_height = kura.blocks_count();
    if durable_height != logical_height {
        return Err(format!(
            "post-snapshot Kura durable height {durable_height} differs from logical height {logical_height}"
        ));
    }
    if committed_height > durable_height {
        return Err(format!(
            "post-snapshot State height {committed_height} exceeds reconciled Kura height {durable_height}"
        ));
    }
    if block_count.0 != durable_height {
        iroha_logger::warn!(
            committed_height,
            previous_block_count = block_count.0,
            durable_height,
            "Replacing startup block count with the exact post-snapshot Kura height"
        );
    }
    block_count.0 = durable_height;
    Ok(())
}
fn apply_state_runtime_config_before_snapshot_auth(
    state: &mut State,
    config: &Config,
) -> Result<(), iroha_core::pipeline_validity_policy::PipelineValidityPolicyError> {
    // These fields are process-local execution policy and do not touch Kura-owned geometry.
    // Settlement must be installed before replay because historical
    // transitions resolve their deterministic execution state through
    // `State::settlement`. This ordering is replay correctness, not a
    // node-readiness gate.
    install_node_pipeline_config(state, config)?;
    state.set_crypto(config.crypto.clone());
    state.set_oracle(config.oracle.clone());
    state.install_node_fraud_monitoring(config.fraud_monitoring.clone());
    state.set_gov(config.gov.clone());
    state.content = config.content.clone();
    state.set_settlement(config.settlement);
    Ok(())
}
/// Install the node's local pipeline resources; validity and fees are committed.
///
/// Execution limits are committed chain policy
/// (`iroha_core::pipeline_validity_policy`). The node configuration schema holds
/// no such key, so nothing is ignored when the settings come from a file.
fn install_node_pipeline_config(
    state: &mut State,
    config: &Config,
) -> Result<(), iroha_core::pipeline_validity_policy::PipelineValidityPolicyError> {
    let ignored = state.install_node_pipeline(config.pipeline.clone())?;
    if !ignored.is_empty() {
        // Unreachable from a configuration file; a settings value built by hand
        // (a tool or a test) may still hold such values.
        iroha_logger::warn!(
            fields = ?ignored,
            "ignoring pipeline validity values of a hand-built settings value: the committed \
             `pipeline_validity_policy_v1` chain parameter (or the protocol default) decides them"
        );
    }
    Ok(())
}
fn apply_state_geometry_config_before_kura_replay(
    state: &mut State,
    policies: &StartupLanePolicies,
) -> ReportResult<(), StartError> {
    if !state.nexus_runtime_restored_from_snapshot() {
        state
            .prepare_configured_primary_geometry_anchor(&policies.nexus.configured_lane_catalog)
            .map_err(|err| Report::new(err).change_context(StartError::InitKura))
            .map_err(|report| {
                report.attach("failed to anchor authenticated primary lane geometry at startup")
            })?;
        state
            .restore_kura_lane_segments_before_startup_replay()
            .map_err(|err| Report::new(err).change_context(StartError::InitKura))
            .map_err(|report| {
                report.attach("failed to restore primary geometry before startup replay")
            })?;
    } else {
        state
            .prepare_restored_configured_primary_geometry_anchor(
                &policies.nexus.configured_lane_catalog,
            )
            .map_err(|err| Report::new(err).change_context(StartError::InitKura))
            .map_err(|report| {
                report.attach(
                    "failed to anchor snapshot-authenticated primary lane geometry at startup",
                )
            })?;
        state
            .restore_kura_lane_segments_from_nexus()
            .map_err(|err| Report::new(err).change_context(StartError::InitKura))
            .map_err(|report| {
                report.attach("failed to restore snapshot Nexus lane storage at startup")
            })?;
    }
    sccp_staking_policy::validate(&state.world_view(), &policies.nexus.staking)
        .map_err(|error| Report::new(error).change_context(StartError::InitKura))
        .map_err(|report| {
            report.attach(
                "SCCP staking policy does not cover current and retained committee liability",
            )
        })?;
    state
        .set_nexus_from_config(policies.nexus.clone())
        .map_err(|err| Report::new(err).change_context(StartError::InitKura))
        .map_err(|report| {
            report.attach("failed to apply Nexus lane catalog/lifecycle at startup")
        })?;
    Ok(())
}
fn install_zk_config_before_kura_replay(
    state: &mut State,
    config: &Config,
) -> ReportResult<(), StartError> {
    // Validity-affecting ZK values are committed chain policy
    // (`iroha_core::zk_validity_policy`). The node configuration schema holds
    // local resource settings only, so nothing is ignored here.
    let ignored = state
        .install_node_zk(config.zk.clone())
        .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
    if !ignored.is_empty() {
        // Unreachable from a configuration file; a settings value built by hand
        // (a tool or a test) may still hold such values.
        iroha_logger::warn!(
            fields = ?ignored,
            "ignoring ZK validity values of a hand-built settings value: the committed \
             `zk_validity_policy_v1` chain parameter (or the protocol default) decides them"
        );
    }
    Ok(())
}
fn nexus_config_for_startup_replay(
    mut configured: iroha_config::parameters::actual::Nexus,
    restored: Option<&iroha_config::parameters::actual::Nexus>,
) -> iroha_config::parameters::actual::Nexus {
    let Some(restored) = restored else {
        return configured;
    };
    // A snapshot is a committed WSV checkpoint. Preserve its effective catalogs
    // and autoscale cooldown while refreshing static policy from local configuration.
    // The State helper must verify restored dataspaces against the protected World overlay;
    // this projection does not authenticate them or replace the configured baselines.
    configured.lane_catalog = restored.lane_catalog.clone();
    configured.lane_config = restored.lane_config.clone();
    configured.dataspace_catalog = restored.dataspace_catalog.clone();
    configured.autoscale.last_transition_height = restored.autoscale.last_transition_height;
    configured
}
/// Return the effective post-replay Nexus configuration used by runtime
/// admission, routing, and manifest surfaces.
///
/// Replay can commit manual or autoscale lane lifecycle transitions, so the
/// process configuration is no longer authoritative at this boundary.
fn nexus_for_runtime_surfaces(state: &State) -> iroha_config::parameters::actual::Nexus {
    state.nexus_snapshot()
}
/// Freeze the immutable configured manifest baseline used to reconstruct State from Kura.
///
/// Runtime lane manifests come only from the protected cumulative World overlay. They must never
/// enter the local source scan or replace the digest of retained predecessor execution policy.
/// The caller derives effective coverage with `State::lane_manifests_with_committed_catalog`.
fn freeze_lane_manifests_for_startup_replay(
    nexus: &iroha_config::parameters::actual::Nexus,
) -> Result<LaneManifestRegistryHandle, GovernanceGuardError> {
    let registry = LaneManifestRegistry::from_config(
        &nexus.configured_lane_catalog,
        &nexus.governance,
        &nexus.registry,
    );
    registry.validate_active_coverage_for_catalog(&nexus.configured_lane_catalog)?;
    Ok(Arc::new(registry))
}
/// Freeze compliance once before snapshot authentication or transaction replay.
///
/// The same immutable engine is installed in State and later shared with Queue. Revalidating its
/// coverage after replay does not rescan mutable policy files.
fn freeze_lane_compliance_for_startup_replay(
    nexus: &iroha_config::parameters::actual::Nexus,
) -> ReportResult<Option<Arc<LaneComplianceEngine>>, StartError> {
    if !nexus.compliance.enabled {
        return Ok(None);
    }
    let dir = nexus.compliance.policy_dir.as_ref().ok_or_else(|| {
        Report::new(StartError::InitKura)
            .attach("lane compliance enabled but no policy_dir configured")
    })?;
    let engine = LaneComplianceEngine::from_directory(dir, nexus.compliance.audit_only)
        .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
    engine
        .validate_active_catalog(&nexus.lane_catalog)
        .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
    Ok(Some(Arc::new(engine)))
}
/// One validated policy snapshot shared by geometry installation, replay and runtime handoff.
///
/// Construct this before publishing governed geometry: State views must never observe an active
/// lane whose manifest or compliance policy has not been installed. Snapshot authentication can
/// use these process-local policies without authorizing any Kura geometry mutation.
struct StartupLanePolicies {
    nexus: iroha_config::parameters::actual::Nexus,
    manifests: LaneManifestRegistryHandle,
    compliance: Option<Arc<LaneComplianceEngine>>,
}

fn install_lane_policies_for_startup_replay(
    state: &mut State,
    configured: iroha_config::parameters::actual::Nexus,
    baseline: &LaneManifestRegistryHandle,
) -> ReportResult<StartupLanePolicies, StartError> {
    let restored = state
        .nexus_runtime_restored_from_snapshot()
        .then(|| state.nexus_snapshot());
    let nexus = state
        .nexus_with_committed_catalog(nexus_config_for_startup_replay(
            configured,
            restored.as_ref(),
        ))
        .map_err(|error| Report::new(error).change_context(StartError::InitKura))
        .map_err(|report| {
            report.attach("restored physical dataspaces differ from protected catalog authority")
        })?;
    let manifests = state
        .lane_manifests_with_committed_catalog(baseline, &nexus)
        .map_err(|error| Report::new(error).change_context(StartError::InitKura))
        .map_err(|report| report.attach("committed lane manifests are invalid before snapshot authentication and Kura replay"))?;
    let compliance = freeze_lane_compliance_for_startup_replay(&nexus)?;
    // Validate every source before changing State, and never rescan the files during handoff.
    state
        .install_materialized_lane_manifests_for_catalog(
            &manifests,
            &nexus.lane_catalog,
            &nexus.governance,
        )
        .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
    state.install_lane_compliance_engine(compliance.clone());
    Ok(StartupLanePolicies {
        nexus,
        manifests,
        compliance,
    })
}

/// Reconstruct the effective sources, including catalog transitions committed during replay.
fn rebind_frozen_lane_manifests_after_startup_replay(
    state: &State,
    nexus: &iroha_config::parameters::actual::Nexus,
) -> Result<LaneManifestRegistryHandle, iroha_core::state::LaneLifecycleError> {
    let installed = state.lane_manifests.read().clone();
    state.lane_manifests_with_committed_catalog(&installed, nexus)
}
#[cfg(test)]
mod startup_runtime_catalog_tests;
#[cfg(test)]
mod startup_runtime_policy_tests;
#[cfg(test)]
mod snapshot_read_error_tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::block::BlockHeader;
    use std::num::NonZeroUsize;
    fn dummy_block_hash(byte: u8) -> HashOf<BlockHeader> {
        let mut bytes = [0u8; Hash::LENGTH];
        bytes[0] = byte;
        HashOf::from_untyped_unchecked(Hash::prehashed(bytes))
    }
    #[test]
    fn snapshot_read_error_classifies_fatal_errors() {
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::NotFound
        ));
        let io = std::io::Error::other("boom");
        assert!(!snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::IO(io, std::path::PathBuf::from("snapshot.data"))
        ));
        assert!(!snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::NetworkIdMismatch {
                expected: NetworkId::from_genesis_hash(dummy_block_hash(1)),
                actual: NetworkId::from_genesis_hash(dummy_block_hash(2)),
            }
        ));
        let incompatible_zk = TryReadSnapshotError::ZkConfigInstall(
            iroha_core::state::ZkConfigInstallError::ConfidentialPolicyTransitionLimitExceeded {
                effective_height: 1,
                count: 2,
                maximum: std::num::NonZeroU32::new(1).expect("nonzero transition cap"),
            },
        );
        assert!(!snapshot_read_error_is_recoverable(&incompatible_zk));
    }
    #[test]
    fn snapshot_state_admission_never_authorizes_empty_state_fallback() {
        use iroha_core::state::{
            BlockHashAdmissionError, MembershipAdmissionError, StateAdmissionError,
            StateStorageAdmissionError,
        };
        let budget = iroha_allocation::AllocationBudget::new(1);
        let _occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        for admission in [
            StateAdmissionError::Storage(StateStorageAdmissionError::World(
                mv::storage::AdmittedStorageError::Allocation(refusal.clone()),
            )),
            StateAdmissionError::Membership(MembershipAdmissionError::Capacity(refusal.clone())),
            StateAdmissionError::History(BlockHashAdmissionError::Capacity(refusal)),
            StateAdmissionError::Membership(MembershipAdmissionError::Allocator {
                requested_bytes: 1,
            }),
            StateAdmissionError::Membership(MembershipAdmissionError::Poisoned),
        ] {
            let error = TryReadSnapshotError::StateAdmission(admission);
            assert!(!snapshot_read_error_is_recoverable(&error));
            for emergency_fast in [false, true] {
                assert!(!snapshot_failure_allows_empty_state_fallback(
                    &error,
                    emergency_fast
                ));
            }
        }
    }
    #[test]
    fn snapshot_integrity_errors_are_recoverable() {
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::ChecksumMismatch {
                expected: "deadbeef".into(),
                actual: "beadfeed".into(),
            }
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::ChecksumMissing(std::path::PathBuf::from("snapshot.sha256"))
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::SignatureMissing(std::path::PathBuf::from("snapshot.sig"))
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::SignatureMalformed("bad sig".into())
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::SignatureInvalid("invalid sig".into())
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MerkleMissing(std::path::PathBuf::from("snapshot.merkle.json"))
        ));
        let json_err = norito::json::from_str::<norito::json::Value>("not json").unwrap_err();
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::Serialization(json_err)
        ));
        let json_err = norito::json::from_str::<norito::json::Value>("not json").unwrap_err();
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MerkleMetadata(json_err)
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MerkleMetadataMalformed("bad merkle".into())
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MerkleMismatch {
                expected: "deadbeef".into(),
                actual: "beadfeed".into(),
            }
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MerkleChunkSizeMismatch {
                expected: NonZeroUsize::new(1).unwrap(),
                actual: NonZeroUsize::new(2).unwrap(),
            }
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MerkleLengthMismatch {
                expected: 10,
                actual: 11,
            }
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MerkleProofInvalid {
                chunk: 0,
                reason: "bad proof".into(),
            }
        ));
    }
    #[test]
    fn snapshot_recovery_rejects_mismatched_height() {
        let mismatched_height = TryReadSnapshotError::MismatchedHeight {
            snapshot_height: 2,
            kura_height: 1,
        };
        assert!(!snapshot_read_error_is_recoverable(&mismatched_height));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MissingBlock { height: 1 }
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MissingSpaceDirectoryManifestSection {
                snapshot_height: 608
            }
        ));
        assert!(snapshot_read_error_is_recoverable(
            &TryReadSnapshotError::MismatchedHash {
                height: 1,
                snapshot_block_hash: dummy_block_hash(1),
                kura_block_hash: dummy_block_hash(2),
            }
        ));
    }
    #[test]
    fn emergency_fast_never_falls_back_to_empty_state() {
        for error in [
            TryReadSnapshotError::NotFound,
            TryReadSnapshotError::ChecksumMismatch {
                expected: "expected".to_owned(),
                actual: "corrupt".to_owned(),
            },
            TryReadSnapshotError::SignatureInvalid("forged signature".to_owned()),
            TryReadSnapshotError::MissingBlock { height: 2 },
        ] {
            assert!(!snapshot_failure_allows_empty_state_fallback(&error, true));
        }
        assert!(snapshot_failure_allows_empty_state_fallback(
            &TryReadSnapshotError::NotFound,
            false
        ));
        assert!(snapshot_failure_allows_empty_state_fallback(
            &TryReadSnapshotError::SignatureInvalid("ordinary corrupt snapshot".to_owned()),
            false
        ));
    }
    #[test]
    fn disabled_snapshot_mode_skips_restore() {
        assert!(snapshot_mode_allows_restore(SnapshotMode::ReadWrite));
        assert!(snapshot_mode_allows_restore(SnapshotMode::Readonly));
        assert!(!snapshot_mode_allows_restore(SnapshotMode::Disabled));
    }
    fn native_snapshot_count_fixture(
        height: u64,
    ) -> iroha_core::sumeragi::test_chain::CertifiedTestChain {
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("execute original signed genesis");
        while chain.height() < height {
            // The fixture supplies an actual clock transaction; native idle chains stay idle.
            chain.commit(Vec::new());
        }
        chain
    }
    #[test]
    fn refresh_block_count_after_snapshot_load_uses_exact_certified_height() {
        let chain = native_snapshot_count_fixture(2);
        let mut block_count = iroha_core::kura::BlockCount(0);
        refresh_block_count_after_snapshot_load(&mut block_count, 2, chain.kura())
            .expect("read exact certified Kura height");
        assert_eq!(block_count.0, 2);
    }
    #[test]
    fn refresh_block_count_after_snapshot_load_uses_exact_higher_kura_height() {
        let chain = native_snapshot_count_fixture(5);
        let mut block_count = iroha_core::kura::BlockCount(9);
        refresh_block_count_after_snapshot_load(&mut block_count, 2, chain.kura())
            .expect("replace stale count with exact certified Kura height");
        assert_eq!(block_count.0, 5);
    }
    #[test]
    fn refresh_block_count_rejects_state_ahead_of_certified_kura() {
        let chain = native_snapshot_count_fixture(1);
        let mut block_count = iroha_core::kura::BlockCount(1);
        assert!(
            refresh_block_count_after_snapshot_load(&mut block_count, 2, chain.kura()).is_err()
        );
        assert_eq!(block_count.0, 1, "failed refresh preserves the prior count");
    }
    #[test]
    fn nonempty_kura_requires_its_original_signed_genesis_body() {
        let chain = native_snapshot_count_fixture(1);
        let count = iroha_core::kura::BlockCount(1);
        let stored = read_stored_genesis_block(
            chain.kura(),
            count,
            &chain.state().view().execution_budget(),
        )
        .expect("read native signed genesis")
        .expect("nonempty chain has genesis");
        assert_eq!(stored.hash(), chain.genesis().hash());
        assert!(
            iroha_data_model::block::SharedSignedBlock::ptr_eq(&stored, chain.committed(1).block(),),
            "startup must retain the original executed genesis graph"
        );
        assert!(stored.belongs_to(&chain.state().ivm_execution_budget()));
        let missing = Kura::blank_kura_for_testing();
        assert!(
            read_stored_genesis_block(&missing, count, &chain.state().view().execution_budget())
                .is_err()
        );
    }
    #[test]
    fn startup_nexus_merge_preserves_snapshot_catalogs_and_cooldown_only() {
        use iroha_config::parameters::actual::LaneConfig as RuntimeLaneConfig;
        use iroha_data_model::nexus::{
            DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig,
        };
        use iroha_model_base::topology::{DataSpaceId, LaneId};
        use std::num::{NonZeroU32, NonZeroU64};
        let catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("nonzero lane namespace"),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "snapshot-lane".to_owned(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("snapshot catalog");
        let dataspaces = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: DataSpaceId::new(42),
                alias: "snapshot-dataspace".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("snapshot dataspace projection");
        let mut restored = iroha_config::parameters::actual::Nexus {
            lane_config: RuntimeLaneConfig::from_catalog(&catalog),
            lane_catalog: catalog.clone(),
            configured_lane_catalog: catalog.clone(),
            dataspace_catalog: dataspaces.clone(),
            configured_dataspace_catalog: dataspaces.clone(),
            ..Default::default()
        };
        restored.autoscale.last_transition_height = 17;
        restored.autoscale.target_block_ms = NonZeroU64::new(777).expect("nonzero target");
        let mut configured = iroha_config::parameters::actual::Nexus::default();
        configured.autoscale.target_block_ms = NonZeroU64::new(321).expect("nonzero target");
        let merged = nexus_config_for_startup_replay(configured, Some(&restored));
        assert_eq!(merged.lane_catalog, catalog);
        assert_eq!(merged.dataspace_catalog, dataspaces);
        assert_eq!(merged.lane_config.entries().len(), 2);
        assert_eq!(merged.autoscale.last_transition_height, 17);
        assert_eq!(merged.autoscale.target_block_ms.get(), 321);
        assert_eq!(
            merged.configured_lane_catalog,
            iroha_data_model::nexus::LaneCatalog::default(),
            "snapshot topology must not replace the process-configured baseline"
        );
        assert_eq!(
            merged.configured_dataspace_catalog,
            DataSpaceCatalog::default(),
            "snapshot dataspaces must not replace the immutable configured baseline"
        );
    }
    #[test]
    fn startup_nexus_merge_uses_config_for_fresh_state() {
        let mut configured = iroha_config::parameters::actual::Nexus::default();
        configured.autoscale.last_transition_height = 9;
        let merged = nexus_config_for_startup_replay(configured, None);
        assert_eq!(
            merged.lane_catalog,
            iroha_data_model::nexus::LaneCatalog::default()
        );
        assert_eq!(merged.autoscale.last_transition_height, 9);
    }
    #[test]
    fn runtime_surfaces_use_post_replay_lane_catalog() {
        use iroha_data_model::nexus::{LaneCatalog, LaneConfig};
        use iroha_model_base::topology::LaneId;
        use std::num::NonZeroU32;
        let configured = iroha_config::parameters::actual::Nexus::default();
        let mut replayed = configured.clone();
        replayed.lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("non-zero lane count"),
            vec![
                LaneConfig::default(),
                LaneConfig {
                    id: LaneId::new(1),
                    alias: "replayed-runtime-lane".to_owned(),
                    ..LaneConfig::default()
                },
            ],
        )
        .expect("valid replayed lane catalog");
        // This selector test supplies an already reconstructed State catalog;
        // it does not execute lifecycle consensus or startup replay. Construct
        // that catalog through the authenticated fixture boundary instead of
        // replacing an existing immutable configured baseline with set_nexus.
        let state = State::new_with_pre_genesis_nexus_for_testing(
            World::new(),
            replayed,
            LiveQueryStore::start_test(),
        );
        let runtime = nexus_for_runtime_surfaces(&state);
        assert_ne!(runtime.lane_catalog, configured.lane_catalog);
        assert!(
            runtime
                .lane_catalog
                .lanes()
                .iter()
                .any(|lane| lane.id == LaneId::new(1)),
            "runtime queue and manifest setup must see the replayed lane"
        );
    }
    #[test]
    fn startup_replay_installs_default_lane_manifest_snapshot_before_validation() {
        use iroha_core::governance::manifest::{GovernanceGuardReason, LaneManifestRegistry};
        use iroha_model_base::topology::LaneId;
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state
            .lane_manifests
            .read()
            .ensure_lane_ready(LaneId::SINGLE)
            .expect("the test constructor binds the default lane manifest");
        state.install_lane_manifests_for_testing(&Arc::new(LaneManifestRegistry::empty()));
        let absent = state
            .lane_manifests
            .read()
            .ensure_lane_ready(LaneId::SINGLE)
            .expect_err("the modeled pre-replay snapshot has no bound manifest catalog");
        assert_eq!(absent.reason(), GovernanceGuardReason::UnknownLane);
        let nexus = iroha_config::parameters::actual::Nexus::default();
        let frozen = freeze_lane_manifests_for_startup_replay(&nexus)
            .expect("default lane is ready in the frozen startup registry");
        state.install_lane_manifests_for_testing(&frozen);
        state
            .lane_manifests
            .read()
            .ensure_lane_ready(LaneId::SINGLE)
            .expect("atomic replay sees the configured default lane");
    }
    #[test]
    fn startup_replay_manifest_freeze_fails_closed_for_missing_governance_source() {
        use iroha_core::governance::manifest::GovernanceGuardReason;
        use iroha_data_model::nexus::{LaneCatalog, LaneConfig};
        use std::num::NonZeroU32;
        let governed_lane = LaneConfig {
            governance: Some("parliament".to_owned()),
            ..LaneConfig::default()
        };
        let catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("non-zero lane namespace"),
            vec![governed_lane],
        )
        .expect("single governed lane catalog");
        let nexus = iroha_config::parameters::actual::Nexus {
            lane_catalog: catalog.clone(),
            configured_lane_catalog: catalog,
            ..Default::default()
        };
        let error = freeze_lane_manifests_for_startup_replay(&nexus)
            .expect_err("governed replay lane without a frozen manifest must reject startup");
        assert_eq!(error.reason(), GovernanceGuardReason::MissingManifest);
    }
    #[test]
    fn post_replay_manifest_rebind_does_not_rescan_changed_sources() {
        let manifest_dir = tempfile::tempdir().expect("create manifest source directory");
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        nexus.registry.manifest_directory = Some(manifest_dir.path().to_path_buf());
        let frozen = freeze_lane_manifests_for_startup_replay(&nexus)
            .expect("ungoverned default lane is ready without a manifest");
        assert!(!frozen.has_manifest_source_alias("default"));
        let state = State::new_for_testing(
            World::new(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        state.install_lane_manifests_for_testing(&frozen);
        std::fs::write(manifest_dir.path().join("default.manifest.json"), b"{}")
            .expect("replace manifest source set after the startup freeze");
        let rebound = rebind_frozen_lane_manifests_after_startup_replay(&state, &nexus)
            .expect("frozen source set deterministically rebinds");
        assert!(!rebound.has_manifest_source_alias("default"));
        assert_eq!(
            rebound.consensus_policy_digest(),
            frozen.consensus_policy_digest(),
            "post-replay rebinding must preserve the pre-replay source snapshot"
        );
        let rescanned = LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &nexus.registry,
        );
        assert!(rescanned.has_manifest_source_alias("default"));
        assert_ne!(
            rescanned.consensus_policy_digest(),
            frozen.consensus_policy_digest(),
            "the adversarial file change would affect a forbidden second scan"
        );
    }
}
fn validate_reputation_runtime_provider_presence(
    runtime_enabled: bool,
    provider_presence: [bool; 4],
) -> Result<(), &'static str> {
    if runtime_enabled {
        match provider_presence {
            [true, true, true, true] => Ok(()),
            [false, _, _, _] => Err(
                "enabled SoraFS reputation runtime requires an injected monotonic journal-checkpoint provider",
            ),
            [true, false, _, _] => Err(
                "enabled SoraFS reputation runtime requires an injected authenticated journal-transaction submitter",
            ),
            [true, true, false, _] => Err(
                "enabled SoraFS reputation runtime requires an injected external threshold signer",
            ),
            [true, true, true, false] => Err(
                "enabled SoraFS reputation runtime requires an injected authenticated Governance DAG adapter",
            ),
        }
    } else if provider_presence == [false; 4] {
        Ok(())
    } else {
        Err("disabled SoraFS reputation runtime rejects unexpected runtime providers")
    }
}
fn validate_governance_dag_service_publisher_binding(
    storage: &iroha_config::parameters::actual::SorafsStorage,
    runtime_signer: Option<&dyn sorafs_node::GovernanceDagRuntimeSigner>,
) -> Result<(), sorafs_node::GovernanceDagServiceError> {
    if !storage.governance_dag_service.enabled {
        return Ok(());
    }
    let producer_public_key_hex = storage
        .governance_dag_publisher_public_key_hex
        .as_deref()
        .ok_or_else(|| {
            sorafs_node::GovernanceDagServiceError::Config(
                "enabled Governance DAG service requires the embedded producer public-key binding"
                    .to_owned(),
            )
        })?;
    let service_public_key_hex = storage
        .governance_dag_service
        .publisher_public_key_hex
        .as_deref()
        .ok_or_else(|| {
            sorafs_node::GovernanceDagServiceError::Config(
                "enabled Governance DAG service requires its publisher public key".to_owned(),
            )
        })?;
    if service_public_key_hex != producer_public_key_hex {
        return Err(sorafs_node::GovernanceDagServiceError::Config(
            "Governance DAG service publisher public key does not match the embedded producer configuration"
                .to_owned(),
        ));
    }
    let runtime_public_key_hex = runtime_signer
        .map(|signer| hex::encode(signer.public_key()))
        .ok_or_else(|| {
            sorafs_node::GovernanceDagServiceError::Config(
                "enabled Governance DAG service requires the embedded producer runtime signer"
                    .to_owned(),
            )
        })?;
    if runtime_public_key_hex != producer_public_key_hex {
        return Err(sorafs_node::GovernanceDagServiceError::Config(
            "Governance DAG service publisher public key does not match the embedded producer runtime signer"
                .to_owned(),
        ));
    }
    Ok(())
}
fn resolve_governance_dag_service_launch(
    storage: &iroha_config::parameters::actual::SorafsStorage,
    runtime_deps: &IrohaRuntimeDeps,
) -> Result<
    Option<(
        iroha_config::parameters::actual::SorafsGovernanceDagServiceView,
        sorafs_node::GovernanceDagServiceRuntimeProviders,
    )>,
    sorafs_node::GovernanceDagServiceError,
> {
    let public_service_provider_presence = [
        runtime_deps
            .sorafs_governance_dag_ipfs_authenticator
            .is_some(),
        runtime_deps
            .sorafs_governance_dag_head_authenticator
            .is_some(),
    ];
    validate_governance_dag_service_publisher_binding(
        storage,
        runtime_deps.sorafs_governance_dag_signer.as_deref(),
    )?;
    if !storage.governance_dag_service.enabled {
        if public_service_provider_presence
            .into_iter()
            .any(|present| present)
        {
            return Err(sorafs_node::GovernanceDagServiceError::Config(
                "disabled Governance DAG service rejects unexpected public-service runtime providers"
                    .to_owned(),
            ));
        }
        return Ok(None);
    }
    let mut providers = sorafs_node::GovernanceDagServiceRuntimeProviders::default();
    if let Some(authenticator) = runtime_deps
        .sorafs_governance_dag_ipfs_authenticator
        .as_ref()
    {
        providers = providers.with_ipfs_authenticator(Arc::clone(authenticator));
    }
    if let Some(authenticator) = runtime_deps
        .sorafs_governance_dag_head_authenticator
        .as_ref()
    {
        providers = providers.with_head_authenticator(Arc::clone(authenticator));
    }
    if let Some(checkpoint_store) = runtime_deps.sorafs_governance_dag_checkpoint_store.as_ref() {
        providers = providers.with_checkpoint_store(Arc::clone(checkpoint_store));
    }
    let view = iroha_config::parameters::actual::SorafsGovernanceDagServiceView {
        source_dir: storage.governance_dag_dir.clone(),
        producer_publisher_peer_id: storage.governance_dag_publisher_peer_id.clone(),
        producer_signer_handle: storage.governance_dag_signer_handle.clone(),
        producer_signer_revision: storage.governance_dag_signer_revision,
        producer_signer_policy_digest: storage.governance_dag_signer_policy_digest,
        producer_publisher_public_key_hex: storage.governance_dag_publisher_public_key_hex.clone(),
        service: storage.governance_dag_service.clone(),
    };
    sorafs_node::validate_governance_dag_service_runtime_providers(&view, &providers)?;
    Ok(Some((view, providers)))
}
fn validate_reputation_archive_presence(
    runtime_enabled: bool,
    archive_present: bool,
) -> Result<(), &'static str> {
    match (runtime_enabled, archive_present) {
        (true, true) | (false, false) => Ok(()),
        (true, false) => Err(
            "enabled SoraFS reputation runtime requires its daemon-owned archive before Sumeragi startup",
        ),
        (false, true) => {
            Err("disabled SoraFS reputation runtime rejects an unexpected Sumeragi archive")
        }
    }
}
fn validate_provider_ingest_archive_presence(
    runtime_enabled: bool,
    archive_present: bool,
) -> Result<(), &'static str> {
    match (runtime_enabled, archive_present) {
        (true, true) | (false, false) => Ok(()),
        (true, false) => Err(
            "enabled SoraFS provider-ingest runtime requires its daemon-owned archive before Sumeragi startup",
        ),
        (false, true) => {
            Err("disabled SoraFS provider-ingest runtime rejects an unexpected finalized archive")
        }
    }
}
fn validate_provider_attestation_journal_activation(
    configured: bool,
    native: bool,
) -> Result<(), &'static str> {
    if configured && !native {
        Err("provider-attestation activation requires the concrete native custody owner")
    } else {
        Ok(())
    }
}

fn validate_sorafs_native_signer_role_presence(
    role: &'static str,
    required: bool,
    configured: bool,
    injected: bool,
) -> Result<(), String> {
    match (required, configured) {
        (true, false) => {
            return Err(format!(
                "required SoraFS {role} signer role is missing its configured binding for storage-enabled durable drain or role generation"
            ));
        }
        (false, true) => {
            return Err(format!(
                "inactive SoraFS {role} signer role rejects a configured binding without storage-enabled durable drain or role generation"
            ));
        }
        _ => {}
    }
    match (configured, injected) {
        (true, false) => Err(format!(
            "configured SoraFS {role} signer role is missing its runtime provider"
        )),
        (false, true) => Err(format!(
            "unconfigured SoraFS {role} signer role rejects an injected runtime provider"
        )),
        _ => Ok(()),
    }
}
const fn sorafs_native_signer_role_required(
    storage_enabled: bool,
    role_generation_enabled: bool,
) -> bool {
    storage_enabled || role_generation_enabled
}
fn validate_selected_sorafs_native_signer_presence(
    role: &'static str,
    required: bool,
    binding: Option<&iroha_config::parameters::actual::SorafsNativeTransactionSignerBinding>,
    injected: bool,
) -> Result<(), String> {
    let native = binding.is_some_and(|binding| binding.software_credential.is_some());
    if native && injected {
        return Err(format!(
            "SoraFS {role} native software custody conflicts with an external adapter"
        ));
    }
    // Runtime credentials use iroha_fs retained native custody on both supported hosts.
    // This is a platform-presence check only; actual DACL/mode, key and State checks stay in
    // the credential loader and qualified role adapter.
    if native && !cfg!(any(unix, windows)) {
        return Err(format!(
            "SoraFS {role} native software custody requires native Unix or Windows runtime credentials"
        ));
    }
    validate_sorafs_native_signer_role_presence(
        role,
        required,
        binding.is_some(),
        injected || native,
    )
}
fn validate_sorafs_native_signer_provider_presence(
    config: &Config,
    runtime_deps: &IrohaRuntimeDeps,
) -> Result<(), String> {
    let configured = &config.torii.sorafs_storage.native_transaction_signers;
    validate_selected_sorafs_native_signer_presence(
        "proof_outcome",
        sorafs_native_signer_role_required(config.torii.sorafs_storage.enabled, false),
        configured.proof_outcome.as_ref(),
        runtime_deps.sorafs_proof_outcome_signer.is_some(),
    )?;
    validate_selected_sorafs_native_signer_presence(
        "repair",
        sorafs_native_signer_role_required(
            config.torii.sorafs_storage.enabled,
            config.torii.sorafs_repair.enabled,
        ),
        configured.repair.as_ref(),
        runtime_deps.sorafs_repair_transaction_signer.is_some(),
    )?;
    validate_selected_sorafs_native_signer_presence(
        "reserve",
        sorafs_native_signer_role_required(
            config.torii.sorafs_storage.enabled,
            config.torii.sorafs_storage.reserve_worker.enabled,
        ),
        configured.reserve.as_ref(),
        runtime_deps.sorafs_reserve_transaction_signer.is_some(),
    )?;
    validate_selected_sorafs_native_signer_presence(
        "orderbook",
        sorafs_native_signer_role_required(
            config.torii.sorafs_storage.enabled,
            config.torii.sorafs_storage.orderbook_worker.enabled,
        ),
        configured.orderbook.as_ref(),
        runtime_deps.sorafs_orderbook_transaction_signer.is_some(),
    )
}
fn qualify_soracloud_runtime_signer_for_startup(
    production_mode: bool,
    configured: Option<&iroha_config::parameters::actual::SoracloudRuntimeMutationSignerBinding>,
    runtime_deps: &mut IrohaRuntimeDeps,
) -> Result<(), &'static str> {
    let injected = runtime_deps.soracloud_runtime_mutation_signer.take();
    match (configured, injected) {
        (None, None) if production_mode => {
            Err("production mode requires an exact configured signer binding")
        }
        (None, None) => Ok(()),
        (None, Some(_)) => Err("an unrequested signer provider was injected"),
        (Some(_), None) => Err("the configured signer provider is missing"),
        (Some(configured), Some(provider)) => {
            let binding =
                soracloud_runtime_signer::SoracloudRuntimeSignerBindingV1::try_from_config(
                    configured,
                )
                .map_err(|_| "configured signer binding is invalid")?;
            runtime_deps.soracloud_runtime_mutation_signer = Some(
                soracloud_runtime_signer::qualify_soracloud_runtime_mutation_signer_v1(
                    binding, provider,
                )
                .map_err(
                    |_| "injected signer is substituted, stale, revoked, test-only, or unavailable",
                )?,
            );
            Ok(())
        }
    }
}
/// The node's Sumeragi files and operator choices from its configuration.
fn sumeragi_node_config(
    config: &Config,
    assert_fresh_key: bool,
) -> iroha_core::sumeragi::node::NodeConfig {
    let store_dir = config.kura.store_dir.resolve_relative_path();
    let mut bodies = store_dir.file_name().unwrap_or_default().to_os_string();
    bodies.push("-sumeragi-bodies");
    iroha_core::sumeragi::node::NodeConfig {
        records_dir: config.sumeragi.records_dir.clone(),
        installation_log: config.sumeragi.installation_log.clone(),
        bodies_dir: store_dir.with_file_name(bodies),
        local: config.sumeragi.local,
        assert_fresh_key,
        retired_keys: config.sumeragi.retired_keys.clone(),
    }
}

/// Resolve the writer's signing identity against the same startup verification key.
fn snapshot_signing_key(config: &Config) -> Result<KeyPair, String> {
    let signing = config.snapshot.signing_private_key.as_ref().map_or_else(
        || Ok(config.common.key_pair.clone()),
        |key| KeyPair::from_private_key(key.clone()).map_err(|error| error.to_string()),
    )?;
    let verification = config
        .snapshot
        .verification_public_key
        .as_ref()
        .unwrap_or_else(|| config.common.key_pair.public_key());
    if signing.public_key() != verification {
        return Err("snapshot signing key does not match the configured verification key".into());
    }
    Ok(signing)
}

/// Keep the node's Sumeragi instance until shutdown. A stopped instance (a worker thread
/// ended) ends this task early, so the supervisor shuts the node down: a restart recovers.
async fn supervise_sumeragi(
    node: iroha_core::sumeragi::node::NetworkedNode,
    shutdown_signal: ShutdownSignal,
) {
    let handle = node.handle();
    let stopped = async {
        while handle.driver().stopped().is_none() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    tokio::select! {
        () = shutdown_signal.receive() => {}
        () = stopped => {
            iroha_logger::error!("the Sumeragi instance stopped; shutting the node down");
        }
    }
    let _ = tokio::task::spawn_blocking(move || node.shutdown()).await;
}

mod startup_preparation;
use startup_preparation::{PreparedNative, PreparedStartup, StartupLifetime};

impl Iroha {
    /// Starts Iroha with all its subsystems.
    ///
    /// Returns iroha itself and a future of system shutdown.
    ///
    /// # Errors
    /// - Reading telemetry configs
    /// - Telemetry setup
    /// - Initialization of the native Sumeragi node and [`Kura`]
    pub async fn start(
        build: CompiledBuildMetadata,
        config: Config,
        genesis: Option<GenesisBlock>,
        logger: LoggerHandle,
        shutdown_signal: ShutdownSignal,
    ) -> ReportResult<
        (
            Self,
            impl Future<Output = iroha_futures::supervisor::Result<()>>,
        ),
        StartError,
    > {
        Box::pin(Self::start_with_runtime_deps(
            build,
            config,
            genesis,
            logger,
            shutdown_signal,
            IrohaRuntimeDeps::default(),
            None,
        ))
        .await
    }
    /// Starts Iroha with deployment-owned, runtime-only service dependencies.
    ///
    /// The standard daemon entry point does not adapt the validator node key
    /// into `SoraFS` proof-outcome, repair, reserve/rent, orderbook, moderation,
    /// or Soracloud mutation/provenance authority roles. Those signers, moderation durable
    /// handoffs, and all hedging/billing query, verification, signing,
    /// publication, acknowledgement, and witness adapters must be supplied by
    /// an injecting launcher; enabling the dependent path without one fails
    /// closed. Native preparation executes into the original State before activation; a later
    /// provider refusal retains valid durable genesis while joining this generation's children.
    /// A private Musubi publication runner is likewise assembled only
    /// by an explicitly injected late-bound factory and joins this node's supervisor.
    /// The reputation queue submitter is a separately injected deployment
    /// boundary. The Torii proxy bridge signer remains a separate native node
    /// role. Any configured signed Governance DAG producer requires a sealed
    /// monotonic checkpoint store; enabling its public service additionally
    /// requires separately qualified IPFS/head authenticators. The exact
    /// historical reputation query is daemon-owned and backed only by the
    /// configured Kura-authenticated archive.
    ///
    /// # Errors
    /// - Reading telemetry configs
    /// - Telemetry setup
    /// - Initialization of the native Sumeragi node and [`Kura`]
    pub(crate) async fn start_with_runtime_deps(
        build: CompiledBuildMetadata,
        config: Config,
        genesis: Option<GenesisBlock>,
        logger: LoggerHandle,
        shutdown_signal: ShutdownSignal,
        runtime_deps: IrohaRuntimeDeps,
        musubi_publication_factory: Option<
            Box<dyn musubi_publication_service::MusubiPublicationPrivateServiceFactoryV1>,
        >,
    ) -> ReportResult<
        (
            Self,
            impl Future<Output = iroha_futures::supervisor::Result<()>>,
        ),
        StartError,
    > {
        let prepared = PreparedStartup::prepare(config, genesis).await?;
        Self::activate_with_runtime_deps(
            build,
            prepared,
            logger,
            shutdown_signal,
            runtime_deps,
            musubi_publication_factory,
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    #[iroha_logger::log(name = "start", skip_all)] // This is actually easier to understand as a linear sequence of init statements.
    async fn activate_with_runtime_deps(
        build: CompiledBuildMetadata,
        prepared: PreparedStartup,
        logger: LoggerHandle,
        shutdown_signal: ShutdownSignal,
        mut runtime_deps: IrohaRuntimeDeps,
        musubi_publication_factory: Option<
            Box<dyn musubi_publication_service::MusubiPublicationPrivateServiceFactoryV1>,
        >,
    ) -> ReportResult<
        (
            Self,
            impl Future<Output = iroha_futures::supervisor::Result<()>>,
        ),
        StartError,
    > {
        let PreparedStartup { native, lifetime } = prepared;
        let PreparedNative {
            mut config,
            mut supervisor,
            kura,
            state,
            live_query_store,
            genesis,
            stored_genesis_block,
            block_count,
            prepared_sumeragi,
            signed_consensus_mode,
            frozen_startup_lane_manifests,
            frozen_startup_lane_compliance,
            expected_network_id,
            snapshot_writer_key,
            snapshot_read_buffer_budget,
            events_sender,
            startup_trace_started_at,
            telemetry_profile,
            #[cfg(feature = "telemetry")]
            metrics,
            #[cfg(feature = "telemetry")]
            state_telemetry,
            #[cfg(feature = "telemetry")]
            streaming_telemetry,
        } = *native;
        let effective_genesis = stored_genesis_block
            .as_ref()
            .map(AsRef::as_ref)
            .or_else(|| genesis.as_ref().map(|genesis| &genesis.0));
        let config_emergency_fast = config.kura.init_mode == InitMode::Fast;
        // Keep the original supervisor outside all fallible activation work so every normal
        // error signals and joins its children before this startup returns. Pin this existing
        // inner future on the heap so the instrumented outer future does not retain its large
        // state inline. Its completed owner still drops before the original cleanup match.
        let result = Box::pin(async {
        let build_identity = build
            .identity()
            .map_err(|error| Report::new(StartError::BuildIdentity).attach(error))?;
        let emergency_fast = config.kura.init_mode == InitMode::Fast;
        if emergency_fast {
            iroha_logger::warn!(
                "emergency Fast startup defers optional Kura-backed SoraFS runtimes and their archive qualification until a Strict restart"
            );
        } else {
            validate_provider_attestation_journal_activation(
                config
                    .torii
                    .sorafs_storage
                    .provider_ingest_runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.provider_attestation_journal.is_some()),
                config
                    .torii
                    .sorafs_storage
                    .provider_ingest_runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.native_completion_credential.is_some()),
            )
            .map_err(|message| Report::new(StartError::StartTorii).attach(message))?;
        }
        if !emergency_fast {
            validate_sorafs_native_signer_provider_presence(&config, &runtime_deps).map_err(
                |error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed SoraFS native signer startup presence preflight: {error}"
                    ))
                },
            )?;
            qualify_soracloud_runtime_signer_for_startup(
                config.soracloud_runtime.production_mode,
                config.soracloud_runtime.submission.signer.as_ref(),
                &mut runtime_deps,
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to qualify Soracloud runtime mutation signer: {error}"
                ))
            })?;
        }
        let sorafs_governance_dag_service_launch = if emergency_fast {
            None
        } else {
            resolve_governance_dag_service_launch(&config.torii.sorafs_storage, &runtime_deps)
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to qualify Governance DAG service runtime providers: {error}"
                    ))
                })?
        };
        if !emergency_fast {
            validate_reputation_runtime_provider_presence(
                config.torii.sorafs_storage.reputation_runtime.is_some(),
                [
                    runtime_deps
                        .sorafs_reputation_journal_checkpoint_provider
                        .is_some(),
                    runtime_deps
                        .sorafs_reputation_journal_transaction_submitter
                        .is_some(),
                    runtime_deps.sorafs_reputation_threshold_signer.is_some(),
                    runtime_deps.sorafs_reputation_governance_dag.is_some(),
                ],
            )
            .map_err(|message| Report::new(StartError::StartTorii).attach(message))?;
        }
        #[cfg(any(unix, windows))]
        let native_provider_ingest = if !emergency_fast {
            config
                .torii
                .sorafs_storage
                .provider_ingest_runtime
                .as_ref()
                .filter(|ingest| ingest.native_completion_credential.is_some())
                .map(|ingest| {
                    let roles = &config.torii.sorafs_storage.native_transaction_signers;
                    if ingest.completion_signer_public_key == *config.common.key_pair.public_key()
                        || [
                            &roles.proof_outcome,
                            &roles.repair,
                            &roles.reserve,
                            &roles.orderbook,
                        ]
                        .into_iter()
                        .flatten()
                        .any(|role| role.public_key == ingest.completion_signer_public_key)
                    {
                        return Err(eyre::eyre!(
                            "native completion custody requires a separate role key"
                        ));
                    }
                    let provider = config.torii.sorafs_storage.provider_id.ok_or_else(|| {
                        eyre::eyre!("native provider ingest requires configured provider identity")
                    })?;
                    if runtime_deps
                        .sorafs_provider_ingest_authenticated_source
                        .is_some()
                        || runtime_deps
                            .sorafs_provider_ingest_signer_resolver
                            .is_some()
                        || runtime_deps
                            .sorafs_provider_ingest_checkpoint_runtime
                            .is_some()
                    {
                        return Err(eyre::eyre!(
                            "native provider ingest rejects substituted external adapters"
                        ));
                    }
                    if runtime_deps
                        .sorafs_musubi_provider_attestation_clock_seal
                        .is_some()
                        || runtime_deps
                            .sorafs_musubi_provider_attestation_approval_signer
                            .is_some()
                        || runtime_deps
                            .sorafs_musubi_provider_attestation_inventory
                            .is_some()
                    {
                        return Err(eyre::eyre!(
                            "native provider attestation rejects external adapter substitution"
                        ));
                    }
                    sorafs_provider_ingest_runtime::native_software::NativeProducerV1::prepare(
                        ingest,
                        provider,
                        NetworkId::from_genesis_hash(config.genesis.expected_hash),
                        &config.torii.sorafs_storage.data_dir,
                    )
                })
                .transpose()
                .map_err(|error| {
                    Report::new(StartError::StartTorii)
                        .attach(format!("native provider ingest rejected: {error}"))
                })?
        } else {
            None
        };
        #[cfg(not(any(unix, windows)))]
        if config
            .torii
            .sorafs_storage
            .provider_ingest_runtime
            .as_ref()
            .is_some_and(|ingest| ingest.native_completion_credential.is_some())
        {
            return Err(Report::new(StartError::StartTorii).attach(
                "native provider ingest requires native Unix or Windows credential custody",
            ));
        }
        let sorafs_provider_ingest_preflight = if emergency_fast {
            None
        } else if let Some(provider_ingest_config) =
            config.torii.sorafs_storage.provider_ingest_runtime.as_ref()
        {
            let provider_id = config
                    .torii
                    .sorafs_storage
                    .provider_id
                    .ok_or_else(|| {
                        Report::new(StartError::StartTorii).attach(
                            "enabled SoraFS provider-ingest runtime requires the exact configured storage provider identity",
                        )
                    })?;
            let native_preflight = {
                #[cfg(any(unix, windows))]
                {
                    if let Some(native) = native_provider_ingest.as_ref() {
                        Some(
                            native
                                .preflight(provider_ingest_config, provider_id)
                                .await
                                .map_err(|error| {
                                    Report::new(StartError::StartTorii).attach(format!(
                                        "native provider ingest preflight rejected: {error}"
                                    ))
                                })?,
                        )
                    } else {
                        None
                    }
                }
                #[cfg(not(any(unix, windows)))]
                {
                    None::<sorafs_provider_ingest_runtime::QualifiedProviderIngestRuntimeAdaptersV1>
                }
            };
            if let Some(preflight) = native_preflight {
                Some(preflight)
            } else {
                let authenticated_source = runtime_deps
                    .sorafs_provider_ingest_authenticated_source
                    .clone()
                    .ok_or_else(|| {
                        Report::new(StartError::StartTorii).attach(
                            "enabled SoraFS provider-ingest runtime requires an injected authenticated governed source-fetch adapter",
                        )
                    })?;
                let signer_resolver = runtime_deps
                    .sorafs_provider_ingest_signer_resolver
                    .clone()
                    .ok_or_else(|| {
                        Report::new(StartError::StartTorii).attach(
                            "enabled SoraFS provider-ingest runtime requires an injected governance-aware signer resolver",
                        )
                    })?;
                let checkpoint_runtime = runtime_deps
                    .sorafs_provider_ingest_checkpoint_runtime
                    .clone()
                    .ok_or_else(|| {
                        Report::new(StartError::StartTorii).attach(
                            "enabled SoraFS provider-ingest runtime requires an injected sealed monotonic checkpoint provider",
                        )
                    })?;
                if provider_ingest_config
                    .finalized_archive
                    .retention_authority
                    .is_some()
                    != runtime_deps
                        .sorafs_provider_ingest_retention_authority
                        .is_some()
                {
                    return Err(Report::new(StartError::StartTorii).attach(
                        "SoraFS provider-ingest finalized-archive retention requires exact configured/injected sealed authority presence",
                    ));
                }
                Some(
                    sorafs_provider_ingest_runtime::preflight_runtime_adapters(
                        provider_ingest_config,
                        provider_id,
                        sorafs_provider_ingest_runtime::ProviderIngestRuntimeAdaptersV1::new(
                            authenticated_source,
                            signer_resolver,
                        ),
                        checkpoint_runtime,
                    )
                    .await
                    .map_err(|error| {
                        Report::new(StartError::StartTorii).attach(format!(
                            "failed state-free SoraFS provider-ingest runtime adapter preflight: {error:#}"
                        ))
                    })?,
                )
            }
        } else {
            if runtime_deps
                .sorafs_provider_ingest_authenticated_source
                .is_some()
                || runtime_deps
                    .sorafs_provider_ingest_signer_resolver
                    .is_some()
                || runtime_deps
                    .sorafs_provider_ingest_checkpoint_runtime
                    .is_some()
                || runtime_deps
                    .sorafs_provider_ingest_retention_authority
                    .is_some()
            {
                return Err(Report::new(StartError::StartTorii).attach(
                    "disabled SoraFS provider-ingest runtime rejects unexpected runtime providers",
                ));
            }
            None
        };
        let sorafs_pop_credentials = if emergency_fast {
            None
        } else {
            sorafs_pop_runtime::build(
                config.torii.sorafs_storage.pop_credentials.as_ref(),
                runtime_deps.sorafs_pop_credential_provider_registry.clone(),
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to initialise config-bound SoraFS PoP runtime: {error}"
                ))
            })?
        };
        // Diagnostics share the node's original shutdown owner. Failed activation must not
        // leave a detached infinite thread behind.
        if !emergency_fast {
            let deadlock_shutdown = supervisor.shutdown_signal();
            supervisor.monitor(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = deadlock_shutdown.receive() => break,
                        () = tokio::time::sleep(Duration::from_secs(10)) => {}
                    }
                    for (i, threads) in deadlock::check_deadlock().iter().enumerate() {
                        iroha_logger::error!(deadlock_index = i, thread_count = threads.len(), "deadlock detected");
                        for thread in threads {
                            iroha_logger::error!(deadlock_index = i, thread = ?thread.thread_id(), backtrace = ?thread.backtrace(), "deadlocked thread backtrace");
                        }
                    }
                }
            }));
        }
        // Genesis publication is synchronous and already complete. The background writer
        // starts only after the actual prepared prefix and provider admission both succeed.
        if emergency_fast {
            iroha_logger::warn!("emergency Fast startup did not start the Kura writer; canonical and sidecar persistence remain disabled until a Strict restart");
        } else {
            let child = Kura::start(kura.clone(), supervisor.shutdown_signal())
                .map_err(|err| Report::new(StartError::InitKura).attach(err))?;
            supervisor.monitor(child);
        }
        // Global diagnostic publication is an activation side effect, never a prepared-state
        // or provider-failure side effect. Native preparation owns its direct event sender.
        iroha_core::pipeline::zk_lane::register_events_sender(events_sender.clone());
        // Kura replay can advance consensus-owned Nexus topology beyond the
        // process configuration (manual lifecycle transactions and autoscale
        // transitions both do so). Seed every admission/manifest surface from
        // the effective replayed state, otherwise a restarted node briefly
        // routes with the stale startup catalog and never installs state-side
        // manifest bindings for restored lanes.
        let runtime_nexus = if emergency_fast {
            iroha_config::parameters::actual::Nexus::default()
        } else {
            nexus_for_runtime_surfaces(&state)
        };
        let router: Arc<dyn LaneRouter> = Arc::new(ConfigLaneRouter::new(
            runtime_nexus.routing_policy.clone(),
            runtime_nexus.dataspace_catalog.clone(),
            runtime_nexus.lane_catalog.clone(),
        ));
        let queue_limits = iroha_core::queue::QueueLimits::from_nexus(&runtime_nexus);
        let lane_catalog = Arc::new(runtime_nexus.lane_catalog.clone());
        let dataspace_catalog = Arc::new(runtime_nexus.dataspace_catalog.clone());
        let governance_catalog = Arc::new(runtime_nexus.governance.clone());
        let registry_cfg = runtime_nexus.registry.clone();
        let lane_compliance = frozen_startup_lane_compliance;
        if let Some(engine) = lane_compliance.as_ref() {
            engine
                .validate_active_catalog(lane_catalog.as_ref())
                .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
        }
        let mut queue_config = config.queue;
        if emergency_fast {
            queue_config.capacity = std::num::NonZeroUsize::MIN;
            queue_config.capacity_per_user = std::num::NonZeroUsize::MIN;
            queue_config.max_retained_bytes = std::num::NonZeroU64::MIN;
            queue_config.expired_cull_batch = std::num::NonZeroUsize::MIN;
        }
        let queue = Arc::new(Queue::from_config_with_router_limits_and_catalogs(
            queue_config,
            events_sender.clone(),
            router.clone(),
            queue_limits,
            &lane_catalog,
            &dataspace_catalog,
            lane_compliance.clone(),
        ));
        // Replay may have committed catalog transitions. Reconstruct its effective registry from
        // the retained immutable baseline plus protected World additions, without rescanning files.
        let lane_manifests = if emergency_fast {
            Arc::clone(&frozen_startup_lane_manifests)
        } else {
            rebind_frozen_lane_manifests_after_startup_replay(&state, &runtime_nexus)
                .map_err(|error| Report::new(error).change_context(StartError::InitKura))
                .map_err(|report| {
                    report.attach("lane manifest registry is not ready after atomic Kura replay")
                })?
        };
        if emergency_fast {
            // Emergency Fast has no local frozen source and disables queue ingress.
            // State was sealed provisionally before snapshot authentication.
            queue.enter_emergency_fast_startup().map_err(|err| {
                Report::new(StartError::InitKura).attach(format!(
                    "failed to quarantine the emergency Fast queue: {err}"
                ))
            })?;
            queue
                .install_provisional_empty_lane_manifests_for_emergency_fast_startup()
                .map_err(|err| {
                    Report::new(StartError::InitKura).attach(format!(
                        "failed to install provisional emergency Fast queue manifests: {err}"
                    ))
                })?;
        } else {
            queue
                .install_materialized_lane_manifests_with_state(
                    &lane_manifests,
                    &state,
                    &runtime_nexus.lane_catalog,
                    &runtime_nexus.governance,
                )
                .map_err(|error| Report::new(error).change_context(StartError::InitKura))?;
        }
        state
            .telemetry
            .set_lane_manifest_registry(Arc::clone(&lane_manifests));
        for status in lane_manifests.missing_entries() {
            iroha_logger::warn!(
                lane = %status.alias,
                "governance manifest missing; rejecting transactions routed to this lane until a manifest is provisioned"
            );
        }
        #[cfg(feature = "telemetry")]
        let lane_manifest_task = if emergency_fast {
            None
        } else {
            let queue_task = Arc::clone(&queue);
            let telemetry_task = state.telemetry.clone();
            let governance_task = Arc::clone(&governance_catalog);
            let registry_cfg_task = registry_cfg.clone();
            Some((
                queue_task,
                telemetry_task,
                governance_task,
                registry_cfg_task,
            ))
        };
        #[cfg(not(feature = "telemetry"))]
        let lane_manifest_task = if emergency_fast {
            None
        } else {
            let queue_task = Arc::clone(&queue);
            let governance_task = Arc::clone(&governance_catalog);
            let registry_cfg_task = registry_cfg.clone();
            Some((queue_task, governance_task, registry_cfg_task))
        };
        if config.kura.init_mode == InitMode::Fast {
            iroha_logger::warn!(
                "emergency Fast startup disabled transaction admission and proposal selection until a Strict restart"
            );
        }
        // Native lanes retain committed inputs in their own block stores. Ordinary pending
        // admission is local to this process and does not establish finality.
        let compliance_policy_digest = state
            .lane_compliance_engine()
            .map(|engine| engine.consensus_policy_digest());
        let lane_manifest_policy_digest = (!emergency_fast).then(|| {
            state
                .lane_manifests
                .read()
                .baseline_consensus_policy_digest()
        });
        let mut config_caps = if emergency_fast {
            build_consensus_config_caps(
                &config.nexus,
                compliance_policy_digest,
                lane_manifest_policy_digest,
            )
        } else {
            build_consensus_config_caps(
                &state.nexus_snapshot(),
                compliance_policy_digest,
                lane_manifest_policy_digest,
            )
        }?;
        // Peers admit each other by the consensus mode, the Sumeragi protocol version and the
        // instance id (`I`: the genesis block and the chain id) as the consensus fingerprint.
        let consensus_fingerprint = match prepared_sumeragi.as_ref() {
            Some(prepared) => prepared.instance(),
            None => {
                let genesis = effective_genesis.ok_or_else(|| {
                    Report::new(StartError::InitKura)
                        .attach("emergency Fast startup found no signed genesis block")
                })?;
                iroha_core::sumeragi::node::root_instance(genesis, &config.common.chain.to_string())
                    .map_err(|error| Report::new(StartError::InitKura).attach(error))?
            }
        };
        config_caps.native_config_fingerprint = match prepared_sumeragi.as_ref() {
            Some(prepared) => prepared.config_fingerprint().into(),
            None => iroha_core::sumeragi::node::consensus_configuration_fingerprint(
                effective_genesis.ok_or_else(|| {
                    Report::new(StartError::InitKura)
                        .attach("native handshake requires exact signed genesis")
                })?,
            )
            .map_err(|error| Report::new(StartError::InitKura).attach(error))?
            .into(),
        };
        let consensus_caps = iroha_p2p::ConsensusHandshakeCaps {
            mode: signed_consensus_mode,
            proto_version: u32::from(iroha_core::sumeragi::node::PROTOCOL_VERSION),
            consensus_fingerprint: consensus_fingerprint.0,
            config: config_caps,
        };
        // The handshake identifies the release, not the chain's committed ZK
        // policy: a policy an authorized `SetParameter` commits is State, and
        // peers at different heights (a joining node, a node that restarted
        // after the change) must still connect.
        let confidential_features = handshake_confidential_features();
        iroha_logger::info!(
            mode=%consensus_caps.mode.tag(),
            proto=%consensus_caps.proto_version,
            fingerprint=%format!("0x{}", hex::encode(consensus_caps.consensus_fingerprint)),
            "Consensus handshake caps"
        );
        // If a genesis manifest JSON is provided via CLI, validate its crypto and consensus mode.
        let cfg_manifest = config
            .genesis
            .manifest_json
            .as_ref()
            .map(WithOrigin::resolve_relative_path);
        if !emergency_fast && let Some(json_path) = cfg_manifest {
            let manifest = read_genesis_manifest(&json_path)?;
            if let Err(err) = ensure_manifest_crypto_matches(&manifest, &config) {
                return Err(Report::new(StartError::InitKura).attach(format!(
                    "Genesis manifest crypto settings do not match node configuration: {err}"
                )));
            }
            let got =
                iroha_data_model::parameter::system::ConsensusMode::from(manifest.consensus_mode());
            if got != signed_consensus_mode {
                return Err(Report::new(StartError::InitKura).attach(format!(
                    "Genesis manifest consensus_mode mismatch: manifest `{got:?}`, expected `{signed_consensus_mode:?}`"
                )));
            }
        }
        // TODO(F.4): `confidential.enabled` and `confidential.assume_valid` are node-local
        // switches advertised to peers (census entry `cfg.confidential.node_switches`).
        // Remove them together with the handshake fields and the generators that write them.
        let confidential_caps = iroha_p2p::ConfidentialHandshakeCaps {
            enabled: config.confidential.enabled,
            assume_valid: config.confidential.assume_valid,
            verifier_backend: config.confidential.verifier_backend.clone(),
            features: Some(confidential_handshake_policy_digest(confidential_features)),
        };
        let crypto_caps = iroha_p2p::CryptoHandshakeCaps {
            sm_enabled: config.crypto.sm_helpers_enabled(),
            sm_openssl_preview: config.crypto.enable_sm_openssl_preview,
            require_sm_handshake_match: config.network.require_sm_handshake_match,
            require_sm_openssl_preview_match: config.network.require_sm_openssl_preview_match,
        };
        let configured_validator_dial_roster: BTreeSet<_> =
            filter_validators_from_trusted(config.common.trusted_peers.value())
                .into_iter()
                .collect();
        let initial_trusted_sources = config
            .common
            .trusted_peers
            .value()
            .others
            .iter()
            .map(|peer| peer.id().clone())
            .collect();
        let p2p_identity_keys = iroha_p2p::P2pIdentityKeys::new(
            config.common.key_pair.clone(),
            config.common.soranet_transport_key_pair.clone(),
        )
        .attach_with(|| config.network.address.clone().into_attachment())
        .change_context(StartError::StartP2p)?;
        let (network, child) = IrohaNetwork::start_with_crypto_and_initial_authorities(
            p2p_identity_keys,
            config.network.clone(),
            expected_network_id,
            Some(consensus_caps),
            Some(confidential_caps),
            Some(crypto_caps),
            initial_trusted_sources,
            configured_validator_dial_roster.iter().cloned().collect(),
            supervisor.shutdown_signal(),
        )
        .await
        .attach_with(|| config.network.address.clone().into_attachment())
        .change_context(StartError::StartP2p)?;
        supervisor.monitor(child);
        let mut streaming = iroha_core::streaming::StreamingHandle::with_key_material(
            config.streaming.key_material.clone(),
        )
        .with_capabilities(CapabilityFlags::from_bits(config.streaming.feature_bits));
        streaming
            .apply_codec_config(&config.streaming.codec)
            .map_err(|err| Report::new(err).change_context(StartError::StartP2p))?;
        streaming.apply_crypto_config(&config.crypto);
        streaming.apply_sync_config(&config.streaming.sync);
        #[cfg(feature = "telemetry")]
        if let Some(ref telemetry_handle) = streaming_telemetry {
            streaming = streaming.with_telemetry(telemetry_handle.clone());
        }
        if emergency_fast {
            iroha_logger::warn!(
                "emergency Fast startup disabled streaming control and durable session snapshots"
            );
        } else {
            let snapshot_file = config
                .streaming
                .session_store_dir
                .clone()
                .join("sessions.norito");
            streaming.set_snapshot_path(snapshot_file);
            let snapshot_encryption_key =
                iroha_core::streaming::snapshot_session_key(&config.streaming.key_material);
            streaming
                .set_snapshot_encryption_key(&snapshot_encryption_key)
                .map_err(Report::from)
                .change_context(StartError::StartP2p)
                .map_err(|report| {
                    report.attach("failed to configure streaming snapshot encryption")
                })?;
            if let Err(err) = streaming.load_snapshots() {
                iroha_logger::warn!(?err, "Failed to load streaming session snapshots");
            }
        }
        log_startup_trace("irohad.streaming.ready", startup_trace_started_at);
        iroha_core::streaming::set_global_handle(streaming.clone());
        if !emergency_fast {
            let streaming_events_handle = streaming.clone();
            let ticket_events_rx = events_sender.subscribe();
            supervisor.monitor(tokio::spawn(async move {
                run_ticket_event_listener(streaming_events_handle, ticket_events_rx).await;
            }));
        }
        // Recovery: scan recent persisted pipeline sidecars and log DAG fingerprint mismatches (best-effort).
        #[cfg(feature = "dag-recovery-verify")]
        if !emergency_fast {
            use iroha_core::pipeline::access::{IvmStrategy, derive_for_transaction};
            use sha2::{Digest, Sha256};
            // Choose strategy based on configured pipeline prepass
            let view = state.query_view();
            let dyn_pre = state.pipeline_snapshot().dynamic_prepass;
            let strategy = if dyn_pre {
                IvmStrategy::DynamicThenConservative
            } else {
                IvmStrategy::Conservative
            };
            // Deterministic fingerprint over interned access ids + call hashes
            fn fp_from_access(
                key_count: usize,
                access: &[iroha_core::pipeline::access::AccessSet],
                call_hashes: &[iroha_crypto::HashOf<
                    iroha_data_model::transaction::signed::TransactionEntrypoint,
                >],
            ) -> [u8; 32] {
                use std::collections::BTreeMap;
                let mut map: BTreeMap<&str, u32> = BTreeMap::new();
                for aset in access.iter() {
                    for k in aset.read_keys.iter() {
                        map.entry(k.as_str()).or_insert(u32::MAX);
                    }
                    for k in aset.write_keys.iter() {
                        map.entry(k.as_str()).or_insert(u32::MAX);
                    }
                }
                let mut next: u32 = 0;
                for v in map.values_mut() {
                    *v = next;
                    next = next.saturating_add(1);
                }
                let mut hasher = Sha256::new();
                hasher.update(&(key_count as u64).to_le_bytes());
                for aset in access.iter() {
                    hasher.update(&(aset.read_keys.len() as u64).to_le_bytes());
                    for k in aset.read_keys.iter() {
                        let id = *map.get(k.as_str()).expect("interned");
                        hasher.update(&id.to_le_bytes());
                    }
                    hasher.update(&(aset.write_keys.len() as u64).to_le_bytes());
                    for k in aset.write_keys.iter() {
                        let id = *map.get(k.as_str()).expect("interned");
                        hasher.update(&id.to_le_bytes());
                    }
                }
                for ch in call_hashes.iter() {
                    hasher.update(ch.as_ref());
                }
                hasher.finalize().into()
            }
            // Scan recent blocks for persisted sidecars and compare fingerprints
            let scan_n: usize = 16;
            let total = block_count.0;
            let start = total.saturating_sub(scan_n) + 1;
            for h in start..=total {
                if let Some(sidecar) = kura.read_pipeline_metadata(h as u64) {
                    let exp = sidecar.dag.fingerprint;
                    if let Some(height) = std::num::NonZeroUsize::new(h) {
                        if let Some(block) = kura
                            .get_block(height, &view.execution_budget())
                            .map_err(|error| {
                                Report::new(error).change_context(StartError::InitKura)
                            })?
                        {
                            let txs: Vec<&iroha_data_model::transaction::SignedTransaction> =
                                block.external_transactions().collect();
                            let access: Vec<_> = txs
                                .iter()
                                .map(|tx| derive_for_transaction(tx, Some(&view), strategy))
                                .collect();
                            use std::collections::BTreeSet;
                            let mut keys = BTreeSet::new();
                            for aset in access.iter() {
                                for k in aset.read_keys.iter() {
                                    keys.insert(k.as_str());
                                }
                                for k in aset.write_keys.iter() {
                                    keys.insert(k.as_str());
                                }
                            }
                            let key_count = keys.len();
                            let call_hashes: Vec<_> =
                                txs.iter().map(|tx| tx.hash_as_entrypoint()).collect();
                            let got = fp_from_access(key_count, &access, &call_hashes);
                            if got != exp {
                                iroha_logger::warn!(
                                    height = h,
                                    expected=%hex::encode(exp),
                                    actual=%hex::encode(got),
                                    "startup: pipeline DAG fingerprint mismatch (persisted vs recomputed)"
                                );
                            }
                        }
                    }
                }
            }
        }
        #[cfg(not(feature = "dag-recovery-verify"))]
        if !emergency_fast {
            // Recovery sidecar scan is optional and only used for diagnostics; keep it lightweight
            let scan_n: usize = 16;
            let total = block_count.0;
            let start = total.saturating_sub(scan_n) + 1;
            for h in start..=total {
                if kura.read_pipeline_metadata(h as u64).is_some() {
                    iroha_logger::debug!(height = h, "found pipeline recovery sidecar");
                }
            }
        }
        let state: Arc<State> = Arc::from(state);
        #[cfg(any(unix, windows))]
        if let Some(native) = native_provider_ingest.as_ref() {
            native.bind_state(Arc::clone(&state)).map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "native provider ingest State binding rejected: {error}"
                ))
            })?;
        }
        #[cfg(feature = "telemetry")]
        if let Some((queue_task, telemetry_task, governance_task, registry_cfg_task)) =
            lane_manifest_task
        {
            let state_task = Arc::clone(&state);
            let watcher_shutdown = supervisor.shutdown_signal();
            supervisor.monitor(tokio::spawn(async move {
                queue_task
                    .watch_lane_manifests_task(
                        Some(telemetry_task),
                        governance_task,
                        registry_cfg_task,
                        Some(state_task),
                    )
                    .await;
                // A disabled or refused diagnostic refresh may finish normally. Preserve that
                // behavior while retaining this task under the original cleanup owner.
                watcher_shutdown.receive().await;
            }));
        }
        #[cfg(not(feature = "telemetry"))]
        if let Some((queue_task, governance_task, registry_cfg_task)) = lane_manifest_task {
            let state_task = Arc::clone(&state);
            let watcher_shutdown = supervisor.shutdown_signal();
            supervisor.monitor(tokio::spawn(async move {
                queue_task
                    .watch_lane_manifests_task(
                        None,
                        governance_task,
                        registry_cfg_task,
                        Some(state_task),
                    )
                    .await;
                // A disabled or refused diagnostic refresh may finish normally. Preserve that
                // behavior while retaining this task under the original cleanup owner.
                watcher_shutdown.receive().await;
            }));
        }
        #[cfg(feature = "telemetry")]
        let telemetry = if emergency_fast || !telemetry_profile.metrics_enabled() {
            iroha_core::telemetry::Telemetry::from(state_telemetry.clone())
        } else {
            let (telemetry, child) = iroha_core::telemetry::start(
                metrics,
                Arc::clone(&state),
                kura.clone(),
                queue.clone(),
                network.online_peers_receiver(),
                config.common.peer.id.clone(),
                TimeSource::new_system(),
                telemetry_profile.metrics_enabled(),
            )
            .change_context(StartError::StartTorii)
            .attach("register authoritative Kura resource telemetry before serving diagnostics")?;
            supervisor.monitor(child);
            telemetry
        };
        #[cfg(feature = "telemetry")]
        if !emergency_fast && telemetry_profile.metrics_enabled() {
            start_telemetry(&logger, &config, &telemetry, &mut supervisor).await;
            log_startup_trace("irohad.telemetry.ready", startup_trace_started_at);
        }
        let peers_gossiper_topology_events = events_sender.subscribe();
        let (peers_gossiper, child) = PeersGossiper::start(
            config.common.peer.id.clone(),
            expected_network_id,
            config.common.trusted_peers.value().clone(),
            configured_validator_dial_roster,
            config.common.key_pair.clone(),
            config.network.peer_gossip_period,
            config.network.peer_gossip_max_period,
            signed_consensus_mode,
            config.network.trust_decay_half_life,
            config.network.trust_penalty_bad_gossip,
            config.network.trust_penalty_unknown_peer,
            config.network.trust_min_score,
            network.clone(),
            supervisor.shutdown_signal(),
        );
        supervisor.monitor(child);
        let peers_gossiper_topology_state = Arc::clone(&state);
        let peers_gossiper_topology_handle = peers_gossiper.clone();
        let peers_gossiper_topology_shutdown = supervisor.shutdown_signal();
        supervisor.monitor(tokio::spawn(async move {
            peers_gossiper_topology_sync::run(
                peers_gossiper_topology_state,
                peers_gossiper_topology_handle,
                peers_gossiper_topology_events,
                peers_gossiper_topology_shutdown,
            )
            .await;
        }));
        log_startup_trace("irohad.peers_gossiper.ready", startup_trace_started_at);
        #[cfg(feature = "telemetry")]
        let torii_telemetry =
            iroha_torii::MaybeTelemetry::from_profile(Some(telemetry.clone()), telemetry_profile);
        #[cfg(not(feature = "telemetry"))]
        let torii_telemetry = iroha_torii::MaybeTelemetry::from_profile(None, telemetry_profile);
        let mut prepared_sorafs_provider_ingest_archive = if emergency_fast {
            None
        } else if let Some(provider_ingest_config) =
            config.torii.sorafs_storage.provider_ingest_runtime.as_ref()
        {
            let provider_id = config
                    .torii
                    .sorafs_storage
                    .provider_id
                    .ok_or_else(|| {
                        Report::new(StartError::StartP2p).attach(
                            "enabled provider-ingest archive requires the exact configured storage provider identity",
                        )
                    })?;
            let prepared =
                    sorafs_provider_ingest_finalized_query::prepare_provider_ingest_finalized_archive_v1(
                        &provider_ingest_config.finalized_archive,
                        NetworkId::from_genesis_hash(config.genesis.expected_hash),
                        provider_id,
                        &config.kura.store_dir.resolve_relative_path(),
                        &state,
                        &kura,
                        runtime_deps
                            .sorafs_provider_ingest_retention_authority
                            .clone(),
                    )
                    .map_err(|error| {
                        Report::new(StartError::StartP2p).attach(format!(
                            "failed to qualify the daemon-owned finalized provider-ingest archive before Sumeragi startup: {error}"
                        ))
                    })?;
            if let Some(retention) = prepared.retention_authority() {
                iroha_logger::info!(
                    authority_handle = retention.authority().handle(),
                    authority_revision = retention.binding().qualification().revision(),
                    "qualified deployment-owned provider-ingest archive retention authority"
                );
            }
            match prepared.startup_mode() {
                sorafs_provider_ingest_finalized_query::ProviderIngestFinalizedArchiveStartupModeV1::BootstrapAwaitingGenesisCapture => {
                    iroha_logger::info!(
                        state_height = 0,
                        kura_tip_height = 0,
                        "opened empty daemon-owned finalized provider-ingest archive; genesis capture will establish its first anchor"
                    );
                }
                sorafs_provider_ingest_finalized_query::ProviderIngestFinalizedArchiveStartupModeV1::Qualified {
                    reconciliation,
                    live_qualification,
                } => {
                    if reconciliation.activation_floor_created() {
                        iroha_logger::warn!(
                            activation_floor_height =
                                reconciliation.qualification().activation_floor().height,
                            "finalized provider-ingest archive established an explicit activation floor; earlier historical coverage is unavailable"
                        );
                    }
                    iroha_logger::info!(
                        activation_floor_height = live_qualification.activation_floor().height,
                        archive_tip_height = live_qualification.archive_tip().height,
                        kura_tip_height = live_qualification.kura_tip_height(),
                        lag_blocks = live_qualification.lag_blocks(),
                        "qualified daemon-owned finalized provider-ingest archive"
                    );
                }

            }
            Some(prepared)
        } else {
            None
        };
        validate_provider_ingest_archive_presence(
            !emergency_fast
                && config
                    .torii
                    .sorafs_storage
                    .provider_ingest_runtime
                    .is_some(),
            prepared_sorafs_provider_ingest_archive.is_some(),
        )
        .map_err(|message| Report::new(StartError::StartP2p).attach(message))?;
        let sorafs_provider_ingest_finalized_query = prepared_sorafs_provider_ingest_archive
            .as_ref()
            .map(|prepared| Arc::clone(prepared.query()));
        let sorafs_provider_ingest_runtime_query = prepared_sorafs_provider_ingest_archive
            .as_ref()
            .map(|prepared| Arc::clone(prepared.runtime_query()));
        let sorafs_reputation_retention_authority =
            runtime_deps.sorafs_reputation_retention_authority.clone();
        if !emergency_fast
            && config.torii.sorafs_storage.reputation_runtime.is_none()
            && sorafs_reputation_retention_authority.is_some()
        {
            return Err(Report::new(StartError::StartP2p).attach(
                "disabled SoraFS reputation runtime rejects an unexpected finalized-archive retention authority",
            ));
        }
        let prepared_sorafs_reputation_archive = if emergency_fast {
            None
        } else if let Some(reputation_config) =
            config.torii.sorafs_storage.reputation_runtime.as_ref()
        {
            let prepared =
                    sorafs_reputation_finalized_query::prepare_reputation_finalized_archive_v1(
                        reputation_config,
                        &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                        &state,
                        &kura,
                        sorafs_reputation_retention_authority.clone(),
                    )
                    .map_err(|error| {
                        Report::new(StartError::StartP2p).attach(format!(
                            "failed to qualify the daemon-owned finalized reputation archive before Sumeragi startup: {error}"
                        ))
                    })?;
            if let Some(retention) = prepared.retention_authority() {
                iroha_logger::info!(
                    authority_handle = retention.authority().handle(),
                    authority_revision = retention.binding().qualification().revision(),
                    "qualified deployment-owned finalized reputation archive retention authority"
                );
            }
            match prepared.startup_mode() {
                sorafs_reputation_finalized_query::ReputationFinalizedArchiveStartupModeV1::BootstrapAwaitingGenesisCapture => {
                    iroha_logger::info!(
                        state_height = 0,
                        kura_tip_height = 0,
                        "opened empty daemon-owned finalized reputation archive; genesis capture will establish its first anchor"
                    );
                }
                sorafs_reputation_finalized_query::ReputationFinalizedArchiveStartupModeV1::Qualified {
                    reconciliation,
                    live_qualification,
                } => {
                    if reconciliation.activation_floor_created() {
                        iroha_logger::warn!(
                            activation_floor_height =
                                reconciliation.qualification().activation_floor().height,
                            "finalized reputation archive established an explicit activation floor; earlier historical coverage is unavailable"
                        );
                    }
                    iroha_logger::info!(
                        activation_floor_height = live_qualification.activation_floor().height,
                        archive_tip_height = live_qualification.archive_tip().height,
                        kura_tip_height = live_qualification.kura_tip_height(),
                        lag_blocks = live_qualification.lag_blocks(),
                        "qualified daemon-owned finalized reputation archive"
                    );
                }

            }
            Some(prepared)
        } else {
            None
        };
        validate_reputation_archive_presence(
            !emergency_fast && config.torii.sorafs_storage.reputation_runtime.is_some(),
            prepared_sorafs_reputation_archive.is_some(),
        )
        .map_err(|message| Report::new(StartError::StartP2p).attach(message))?;
        let soracloud_runtime_mutation_signer =
            runtime_deps.soracloud_runtime_mutation_signer.clone();
        let soracloud_local_validator_account_id =
            soracloud_runtime_mutation_signer.as_ref().map_or_else(
                || {
                    AccountId::new(
                        config
                            .common
                            .trusted_peers
                            .value()
                            .myself
                            .id()
                            .public_key()
                            .clone(),
                    )
                },
                |signer| signer.authority(),
            );
        let soracloud_local_peer_id = config.common.trusted_peers.value().myself.id().to_string();
        // A failed host prerequisite must not leave newly emitted consensus WAL.
        let prepared_soracloud_runtime = if emergency_fast {
            None
        } else {
            Some(
                SoracloudRuntimeManager::new(
                    soracloud_runtime::SoracloudRuntimeManagerConfig::from_runtime_config(
                        &config.soracloud_runtime,
                    )
                    .with_local_host_identity(
                        soracloud_local_validator_account_id.clone(),
                        soracloud_local_peer_id.clone(),
                    ),
                    Arc::clone(&state),
                )
                .preflight_startup()
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to qualify Soracloud host prerequisites before consensus: {error:#}"
                    ))
                })?,
            )
        };
        let sumeragi = match prepared_sumeragi {
            None => {
                iroha_logger::warn!(
                    "emergency Fast startup left consensus closed and did not start Sumeragi"
                );
                None
            }
            Some(prepared) => {
                prepared
                    .attach_finalized_archives(iroha_core::sumeragi::executor::FinalizedArchives {
                        provider_ingest: prepared_sorafs_provider_ingest_archive
                            .as_ref()
                            .map(|prepared| Arc::clone(prepared.archive())),
                        reputation: prepared_sorafs_reputation_archive
                            .as_ref()
                            .map(|prepared| Arc::clone(prepared.archive())),
                    })
                    .map_err(|error| {
                        Report::new(StartError::StartP2p).attach(format!(
                            "failed to bind current SoraFS finalized archive capture: {error}"
                        ))
                    })?;
                let local_consensus_peer = config.common.trusted_peers.value().myself.id().clone();
                // Consensus-native custody only: a validator seated in the active global-beacon key
                // session must hold its exact partial signer before Sumeragi starts. Governance
                // state never gates startup.
                preflight_threshold_signer_startup_readiness_v1(
                    Arc::clone(&state),
                    local_consensus_peer.clone(),
                    runtime_deps.clone(),
                )
                .await
                .map_err(|message| Report::new(StartError::StartP2p).attach(message))?;
                log_startup_trace("irohad.sumeragi.starting", startup_trace_started_at);
                let node = prepared
                    .start_on_network(
                        iroha_core::sumeragi::node::StartInputs {
                            net: Arc::new(iroha_core::sumeragi::net::P2pNet::new(network.clone())),
                            queue: Arc::clone(&queue),
                            key_pair: config.common.key_pair.clone(),
                            beacon_signer: runtime_deps
                                .sumeragi_global_beacon_partial_signer
                                .clone(),
                            config: sumeragi_node_config(
                                &config,
                                runtime_deps.sumeragi_assert_fresh_key(),
                            ),
                            observer: Arc::new(iroha_core::sumeragi::node::LogObserver),
                            driver: iroha_core::sumeragi::driver::DriverConfig::default(),
                        },
                        network.subscriber_queue_cap().get(),
                    )
                    .map_err(|error| {
                        Report::new(StartError::StartP2p)
                            .attach(format!("failed to start Sumeragi: {error}"))
                    })?;
                let handle = node.handle();
                supervisor.monitor(Child::new(
                    tokio::spawn(supervise_sumeragi(node, supervisor.shutdown_signal())),
                    OnShutdown::Wait(Duration::from_secs(5)),
                ));
                log_startup_trace("irohad.sumeragi.started", startup_trace_started_at);
                Some(handle)
            }
        };
        let tx_gossiper = if emergency_fast {
            iroha_logger::warn!(
                "emergency Fast startup did not launch the transaction-gossip actor"
            );
            TransactionGossiperHandle::emergency_fast_disabled()
        } else {
            let trusted = config.common.trusted_peers.value();
            let self_peer_id = trusted.myself.id().clone();
            let trusted_peers: BTreeSet<_> = std::iter::once(self_peer_id.clone())
                .chain(trusted.others.iter().map(|peer| peer.id().clone()))
                .collect();
            let max_peer_id = trusted_peers
                .iter()
                .max_by_key(|peer_id| peer_id.encoded_len())
                .cloned()
                .unwrap_or_else(|| self_peer_id.clone());
            let (tx_gossiper, child) = TransactionGossiper::from_config(
                config.transaction_gossiper,
                &config.network,
                self_peer_id,
                max_peer_id,
                network.clone(),
                Arc::clone(&queue),
                Arc::clone(&state),
            )
            .start(supervisor.shutdown_signal())
            .map_err(|error| {
                Report::new(StartError::StartP2p)
                    .attach(format!("failed to start transaction gossip: {error}"))
            })?;
            supervisor.monitor(child);
            tx_gossiper
        };
        if let Some(handle) = sumeragi.as_ref() {
            let maker = snapshot_writer_key.and_then(|key| {
                SnapshotMaker::from_config(
                    &config.snapshot,
                    Arc::clone(&state),
                    key,
                    snapshot_read_buffer_budget.clone(),
                )
            });
            // Storage maintenance is authorized only by completed native recovery.
            // A failed consensus owner revokes further snapshot publication.
            supervisor.monitor(SnapshotMaker::start(
                maker,
                Arc::clone(&state),
                handle.startup_recovery(),
                supervisor.shutdown_signal(),
            ));
        }
        let sorafs_storage_config = if emergency_fast {
            sorafs_node::config::StorageConfig::builder()
                .enabled(false)
                .build()
        } else {
            sorafs_node::config::StorageConfig::from(&config.torii.sorafs_storage)
        };
        let sorafs_repair_config = if emergency_fast {
            sorafs_node::config::RepairConfig::default()
        } else {
            sorafs_node::config::RepairConfig::from(&config.torii.sorafs_repair)
        };
        let sorafs_gc_config = if emergency_fast {
            sorafs_node::config::GcConfig::default()
        } else {
            sorafs_node::config::GcConfig::from(&config.torii.sorafs_gc)
        };
        let bootle_lantern_issuance_provider_registry = runtime_deps
            .bootle_lantern_issuance_provider_registry
            .clone();
        let parliament_tle_release_coordinator = runtime_deps.parliament_tle_release_coordinator();
        let moderation_quarantine_key_wrapper =
            runtime_deps.moderation_quarantine_key_wrapper.clone();
        let privacy_cycle_prf_provider = runtime_deps.privacy_cycle_prf_provider.clone();
        let privacy_release_anchor = runtime_deps.privacy_release_anchor.clone();
        let transparency_leader_lease_provider =
            runtime_deps.transparency_leader_lease_provider.clone();
        let sorafs_fenced_transparency_publisher =
            runtime_deps.sorafs_fenced_transparency_publisher.clone();
        let sorafs_fenced_transparency_head_reader =
            runtime_deps.sorafs_fenced_transparency_head_reader.clone();
        let sorafs_governance_dag_signer = runtime_deps.sorafs_governance_dag_signer.clone();
        let sorafs_governance_dag_checkpoint_store =
            runtime_deps.sorafs_governance_dag_checkpoint_store.clone();
        let mut sorafs_stream_token_signer_client =
            runtime_deps.sorafs_stream_token_signer_client.clone();
        let mut sorafs_stream_token_state_observer =
            runtime_deps.sorafs_stream_token_state_observer.clone();
        let mut sorafs_stream_token_approved_anchor =
            runtime_deps.sorafs_stream_token_approved_anchor;
        if !emergency_fast
            && config
                .torii
                .sorafs_storage
                .stream_tokens
                .signer
                .as_ref()
                .is_some_and(|signer| signer.native.is_some())
        {
            if sorafs_stream_token_signer_client.is_some()
                || sorafs_stream_token_state_observer.is_some()
                || sorafs_stream_token_approved_anchor.is_some()
            {
                return Err(Report::new(StartError::StartTorii).attach(
                    "native stream-token custody conflicts with externally supplied adapters",
                ));
            }
            let native = crate::signer_operation::stream_token::native::runtime::build_native_stream_token_runtime_v1(
                &config.torii.sorafs_storage, Arc::clone(&state), Arc::clone(&queue))
                .map_err(|_| Report::new(StartError::StartTorii).attach("configured native stream-token authority unavailable"))?
                .ok_or_else(|| Report::new(StartError::StartTorii).attach("configured native stream-token authority absent"))?;
            sorafs_stream_token_signer_client = Some(native.signer);
            sorafs_stream_token_state_observer = Some(native.observer);
            sorafs_stream_token_approved_anchor = Some(native.anchor);
        }
        // Native consensus is the sole normal-launch gateway admission owner. Assembly rejects
        // injected bare DTO providers before both normal and emergency/disabled selection.
        let sorafs_stream_token_gateway_runtime =
            sorafs_stream_token_gateway_runtime::native::build_native_runtime(
                &config.torii.sorafs_storage.stream_tokens,
                config
                    .torii
                    .sorafs_gateway
                    .compliance
                    .as_ref()
                    .map(|compliance| compliance.gateway_id.as_str()),
                Arc::clone(&state),
                Arc::clone(&queue),
                runtime_deps.sorafs_stream_token_gateway_admission.as_ref(),
                emergency_fast,
            )
            .map_err(|error| Report::new(StartError::StartTorii).attach(error))?;
        let sorafs_appeal_finance_runtime_signers =
            runtime_deps.sorafs_appeal_finance_runtime_signers.clone();
        let sorafs_appeal_finance_checkpoint_runtime = runtime_deps
            .sorafs_appeal_finance_checkpoint_runtime
            .clone();
        #[cfg(any(unix, windows))]
        if !emergency_fast {
            sorafs_native_software_signers::install_native_software_signers(
                &config.torii.sorafs_storage.native_transaction_signers,
                Arc::clone(&state),
                config.common.key_pair.public_key(),
                &mut runtime_deps,
            )
            .map_err(|error| Report::new(StartError::StartTorii).attach(error))?;
        }
        let sorafs_proof_outcome_signer = runtime_deps.sorafs_proof_outcome_signer.clone();
        let sorafs_repair_transaction_signer =
            runtime_deps.sorafs_repair_transaction_signer.clone();
        let sorafs_reserve_transaction_signer =
            runtime_deps.sorafs_reserve_transaction_signer.clone();
        let sorafs_orderbook_transaction_signer =
            runtime_deps.sorafs_orderbook_transaction_signer.clone();
        let soracloud_operator_preseed_store = if !emergency_fast
            && config.soracloud_runtime.inrou.enabled
            && !sorafs_storage_config.enabled()
        {
            let store = Arc::new(
                sorafs_node::store::StorageBackend::new(sorafs_storage_config.clone()).map_err(
                    |error| {
                        Report::new(StartError::StartTorii).attach(format!(
                            "failed to open the local operator-preseed SoraFS store for Inrou hydration: {error}"
                        ))
                    },
                )?,
            );
            let qualified_manifest_digests =
                sorafs_node::operator_preseed::validate_operator_preseed_store_receipts(
                &store,
                sorafs_storage_config.max_capacity_bytes().0,
                &soracloud_local_validator_account_id.to_string(),
                &soracloud_local_peer_id,
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to validate durable local Inrou operator-preseed qualifications: {error}"
                ))
            })?;
            Some((store, qualified_manifest_digests))
        } else {
            None
        };
        let sorafs_moderation_transaction_signer =
            runtime_deps.sorafs_moderation_transaction_signer.clone();
        let sorafs_moderation_settlement_handoff =
            runtime_deps.sorafs_moderation_settlement_handoff.clone();
        let sorafs_moderation_publication_handoff =
            runtime_deps.sorafs_moderation_publication_handoff.clone();
        let sorafs_moderation_panel_notification =
            runtime_deps.sorafs_moderation_panel_notification.clone();
        let sorafs_moderation_panel_notification_archive = runtime_deps
            .sorafs_moderation_panel_notification_archive
            .clone();
        let sorafs_moderation_checkpoint_store =
            runtime_deps.sorafs_moderation_checkpoint_store.clone();
        let sorafs_evidence_viewer_webauthn = runtime_deps.sorafs_evidence_viewer_webauthn.clone();
        let sorafs_evidence_viewer_grants = runtime_deps.sorafs_evidence_viewer_grants.clone();
        let sorafs_evidence_viewer_receipt_signer =
            runtime_deps.sorafs_evidence_viewer_receipt_signer.clone();
        let sorafs_evidence_viewer_erasure = runtime_deps.sorafs_evidence_viewer_erasure.clone();
        let sorafs_evidence_viewer_checkpoint_store =
            runtime_deps.sorafs_evidence_viewer_checkpoint_store.clone();
        let sorafs_evidence_viewer_compaction_archive = runtime_deps
            .sorafs_evidence_viewer_compaction_archive
            .clone();
        let sorafs_evidence_viewer_transparency_publisher = runtime_deps
            .sorafs_evidence_viewer_transparency_publisher
            .clone();
        let sorafs_potr_runtime_signer_roles =
            runtime_deps.sorafs_potr_runtime_signer_roles.clone();
        let sorafs_gateway_acme_client = runtime_deps.sorafs_gateway_acme_client.clone();
        let sorafs_reputation_journal_transaction_submitter_override = runtime_deps
            .sorafs_reputation_journal_transaction_submitter
            .clone();
        let sorafs_reputation_journal_checkpoint_provider = runtime_deps
            .sorafs_reputation_journal_checkpoint_provider
            .clone();
        let sorafs_reputation_threshold_signer =
            runtime_deps.sorafs_reputation_threshold_signer.clone();
        let sorafs_reputation_governance_dag =
            runtime_deps.sorafs_reputation_governance_dag.clone();
        let sorafs_reputation_config = (!emergency_fast)
            .then(|| config.torii.sorafs_storage.reputation_runtime.clone())
            .flatten();
        let sorafs_reserve_transparency_config = (!emergency_fast)
            .then(|| {
                config
                    .torii
                    .sorafs_storage
                    .reserve_transparency_runtime
                    .clone()
            })
            .flatten();
        let sorafs_hedging_billing_finalized_query =
            runtime_deps.sorafs_hedging_billing_finalized_query.clone();
        let sorafs_hedging_billing_journal_verifier =
            runtime_deps.sorafs_hedging_billing_journal_verifier.clone();
        let sorafs_billing_statement_signer = runtime_deps.sorafs_billing_statement_signer.clone();
        let sorafs_billing_statement_publisher =
            runtime_deps.sorafs_billing_statement_publisher.clone();
        let sorafs_billing_acknowledgement_authority = runtime_deps
            .sorafs_billing_acknowledgement_authority
            .clone();
        let sorafs_hedging_billing_epoch_witness_store = runtime_deps
            .sorafs_hedging_billing_epoch_witness_store
            .clone();
        let sorafs_hedging_billing_config = (!emergency_fast)
            .then(|| config.torii.sorafs_storage.hedging_billing_runtime.clone())
            .flatten();
        let sorafs_provider_ingest_config = (!emergency_fast)
            .then(|| config.torii.sorafs_storage.provider_ingest_runtime.clone())
            .flatten();
        let sorafs_provider_ingest_checkpoint_runtime = sorafs_provider_ingest_preflight
            .as_ref()
            .map(sorafs_provider_ingest_runtime::QualifiedProviderIngestRuntimeAdaptersV1::checkpoint_runtime);
        let sorafs_por_finalized_replay_archive =
            runtime_deps.sorafs_por_finalized_replay_archive.clone();
        let mut sorafs_gateway_compliance_feed_transport = runtime_deps
            .sorafs_gateway_compliance_feed_transport
            .clone();
        if !emergency_fast {
            match config.torii.sorafs_gateway.compliance.as_ref() {
                Some(compliance) => {
                    sorafs_gateway_compliance_feed_transport = Some(
                        sorafs_gateway_compliance_transport::resolve(
                            &compliance.feed_transport_provider,
                            &compliance.feeds,
                            sorafs_gateway_compliance_feed_transport.take(),
                        )
                        .map_err(|error| Report::new(StartError::StartTorii).attach(error))?,
                    );
                }
                None if sorafs_gateway_compliance_feed_transport.is_some() => {
                    return Err(Report::new(StartError::StartTorii).attach(
                        "disabled SoraFS gateway compliance rejects an unexpected feed transport",
                    ));
                }
                None => {}
            }
            match (
                config.torii.sorafs_gateway.acme.provider.as_ref(),
                sorafs_gateway_acme_client.as_ref(),
            ) {
                (Some(_), None) => {
                    return Err(Report::new(StartError::StartTorii).attach(
                    "configured SoraFS gateway ACME automation requires the exact deployment-owned ACME client",
                ));
                }
                (None, Some(_)) => {
                    return Err(Report::new(StartError::StartTorii).attach(
                        "unconfigured SoraFS gateway ACME automation rejects an unexpected client",
                    ));
                }
                (Some(_), Some(_)) | (None, None) => {}
            }
        }
        let sorafs_runtime_deps = sorafs_node::NodeRuntimeDeps::default();
        let sorafs_runtime_deps =
            if let Some(key_wrapper) = moderation_quarantine_key_wrapper.as_ref() {
                sorafs_runtime_deps.with_moderation_quarantine_key_wrapper(Arc::clone(key_wrapper))
            } else {
                sorafs_runtime_deps
            };
        let sorafs_runtime_deps = if let Some(provider) = privacy_cycle_prf_provider.as_ref() {
            sorafs_runtime_deps.with_privacy_cycle_prf_provider(Arc::clone(provider))
        } else {
            sorafs_runtime_deps
        };
        let sorafs_runtime_deps = if let Some(anchor) = privacy_release_anchor.as_ref() {
            sorafs_runtime_deps.with_privacy_release_anchor(Arc::clone(anchor))
        } else {
            sorafs_runtime_deps
        };
        let sorafs_runtime_deps =
            if let Some(provider) = transparency_leader_lease_provider.as_ref() {
                sorafs_runtime_deps.with_transparency_leader_lease_provider(Arc::clone(provider))
            } else {
                sorafs_runtime_deps
            };
        let sorafs_runtime_deps =
            if let Some(publisher) = sorafs_fenced_transparency_publisher.as_ref() {
                sorafs_runtime_deps.with_fenced_transparency_publisher(Arc::clone(publisher))
            } else {
                sorafs_runtime_deps
            };
        let sorafs_runtime_deps =
            if let Some(reader) = sorafs_fenced_transparency_head_reader.as_ref() {
                sorafs_runtime_deps.with_fenced_transparency_head_reader(Arc::clone(reader))
            } else {
                sorafs_runtime_deps
            };
        let sorafs_runtime_deps = if let Some(signer) = sorafs_governance_dag_signer.as_ref() {
            sorafs_runtime_deps.with_governance_dag_signer(Arc::clone(signer))
        } else {
            sorafs_runtime_deps
        };
        let sorafs_runtime_deps = if let Some(checkpoint_store) =
            sorafs_governance_dag_checkpoint_store.as_ref()
        {
            sorafs_runtime_deps.with_governance_dag_checkpoint_store(Arc::clone(checkpoint_store))
        } else {
            sorafs_runtime_deps
        };
        let sorafs_runtime_deps =
            if let Some(runtime) = sorafs_provider_ingest_checkpoint_runtime.as_ref() {
                sorafs_runtime_deps.with_provider_ingest_checkpoint_runtime(Arc::clone(runtime))
            } else {
                sorafs_runtime_deps
            };
        let sorafs_runtime_deps =
            if let Some(archive) = sorafs_por_finalized_replay_archive.as_ref() {
                sorafs_runtime_deps.with_por_finalized_replay_archive(Arc::clone(archive))
            } else {
                sorafs_runtime_deps
            };
        let mut sorafs_node = if emergency_fast {
            None
        } else {
            Some(
                sorafs_node::NodeHandle::try_new_with_policies_and_runtime_deps(
                    sorafs_storage_config,
                    sorafs_repair_config,
                    sorafs_gc_config,
                    sorafs_runtime_deps,
                )
                .map_err(|err| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to initialise embedded SoraFS runtime: {err}"
                    ))
                })?,
            )
        };
        let mut sorafs_provider_ingest_completed_musubi_capture = match (
            prepared_sorafs_provider_ingest_archive.as_mut(),
            sorafs_provider_ingest_config.as_ref(),
        ) {
            (Some(prepared), Some(provider_ingest_config)) => Some(
                sorafs_provider_ingest_runtime::compose_inert_completed_musubi_capture_coordinator_v1(
                    sorafs_node
                        .as_ref()
                        .expect("provider ingest is disabled during emergency Fast startup"),
                    prepared,
                    NetworkId::from_genesis_hash(config.genesis.expected_hash),
                    provider_ingest_config.max_page_rows,
                )
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to reserve the inert completed-Musubi capture coordinator: {error:#}"
                    ))
                })?,
            ),
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                return Err(Report::new(StartError::StartTorii).attach(
                    "provider-ingest archive and runtime configuration diverged before inert completed-Musubi capture composition",
                ));
            }
        };
        #[cfg(any(unix, windows))]
        let native_provider_attestation_inventory = if let Some((native, ingest, journal)) =
            native_provider_ingest.as_ref().and_then(|native| {
                let ingest = sorafs_provider_ingest_config.as_ref()?;
                Some((
                    native,
                    ingest,
                    ingest.provider_attestation_journal.as_ref()?,
                ))
            }) {
            let attestation = native.attestation().ok_or_else(|| {
                Report::new(StartError::StartTorii)
                    .attach("native provider attestation custody is absent")
            })?;
            let coordinator = sorafs_provider_ingest_completed_musubi_capture
                .take()
                .ok_or_else(|| {
                    Report::new(StartError::StartTorii)
                        .attach("native provider attestation capture was already taken")
                })?;
            let (driver, inventory) = attestation
                .compose(
                    sorafs_node
                        .as_ref()
                        .expect("native ingest requires storage"),
                    coordinator,
                    Arc::clone(&state),
                    journal,
                )
                .map_err(|error| {
                    Report::new(StartError::StartTorii)
                        .attach(format!("native attestation composition rejected: {error}"))
                })?;
            let child = sorafs_provider_ingest_runtime::start_native_attestation(
                driver,
                ingest.scan_interval_ms,
                supervisor.shutdown_signal(),
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii)
                    .attach(format!("native attestation supervision rejected: {error}"))
            })?;
            supervisor.monitor(child);
            Some(inventory)
        } else {
            None
        };
        #[cfg(not(any(unix, windows)))]
        let native_provider_attestation_inventory = None;
        if let Some((view, providers)) = sorafs_governance_dag_service_launch {
            let runner = sorafs_node::prepare_governance_dag_service_from_view(view, providers)
                .await
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to prepare the supervised Governance DAG service: {error}"
                    ))
                })?;
            sorafs_node
                .as_mut()
                .expect("Governance DAG service is disabled during emergency Fast startup")
                .install_governance_dag_mirror_read_handle(runner.mirror_read_handle())
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to install the supervised Governance DAG mirror reader: {error}"
                    ))
                })?;
            let service_shutdown = supervisor.shutdown_signal();
            let child = tokio::spawn(async move {
                if let Err(error) =
                    Box::pin(runner.run_until(async move { service_shutdown.receive().await }))
                        .await
                {
                    panic!("supervised Governance DAG service failed: {error}");
                }
            });
            supervisor.monitor(Child::new(
                child,
                OnShutdown::Wait(NODE_RUNTIME_SHUTDOWN_TIMEOUT),
            ));
        }
        let shared_sorafs_cache = if emergency_fast {
            None
        } else {
            build_shared_sorafs_provider_cache(&config, Arc::clone(&state))
                .map_err(Report::new)
                .change_context(StartError::StartTorii)?
        };
        if let Some(source_config) = config
            .torii
            .sorafs_repair
            .source
            .as_ref()
            .filter(|_| !emergency_fast)
        {
            if config
                .torii
                .sorafs_storage
                .native_transaction_signers
                .repair
                .as_ref()
                .is_none_or(|binding| binding.authority != source_config.authority)
            {
                return Err(Report::new(StartError::StartTorii).attach(
                    "remote SoraFS repair requires the configured native repair authority",
                ));
            }
            let cache = shared_sorafs_cache.clone().ok_or_else(|| {
                Report::new(StartError::StartTorii)
                    .attach("remote SoraFS repair requires native provider discovery")
            })?;
            let node = sorafs_node.as_ref().ok_or_else(|| {
                Report::new(StartError::StartTorii)
                    .attach("remote SoraFS repair requires local storage")
            })?;
            let source = sorafs_repair_source::NativeRepairSourceV1::new(
                source_config,
                Arc::clone(&state),
                cache,
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii)
                    .attach(format!("remote SoraFS repair source rejected: {error}"))
            })?;
            node.set_repair_orchestrator(Arc::new(source));
        }
        let sorafs_provider_ingest_runtime = if let Some(provider_ingest_config) =
            sorafs_provider_ingest_config
        {
            let preflight = sorafs_provider_ingest_preflight.ok_or_else(|| {
                Report::new(StartError::StartTorii).attach(
                    "enabled SoraFS provider-ingest runtime has no state-free qualified adapter token",
                )
            })?;
            let (handle, child) = sorafs_provider_ingest_runtime::start(
                provider_ingest_config,
                sorafs_provider_ingest_runtime::ProviderIngestRuntimeStartArgsV1::new(
                    NetworkId::from_genesis_hash(config.genesis.expected_hash),
                    Arc::clone(&state),
                    Arc::clone(&queue),
                    sorafs_node::NodeHandle::clone(
                        sorafs_node
                            .as_ref()
                            .expect("provider ingest is disabled during emergency Fast startup"),
                    ),
                    Arc::clone(
                        sorafs_provider_ingest_runtime_query
                            .as_ref()
                            .ok_or_else(|| {
                                Report::new(StartError::StartTorii).attach(
                                    "enabled SoraFS provider-ingest runtime has no archive-only finalized query installed in Sumeragi",
                                )
                            })?,
                    ),
                ),
                preflight,
                supervisor.shutdown_signal(),
            )
            .await
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to initialise SoraFS provider-ingest runtime: {error:#}"
                ))
            })?;
            supervisor.monitor(child);
            Some(handle)
        } else {
            None
        };
        let sorafs_reputation_runtime = if let Some(reputation_config) =
            sorafs_reputation_config.as_ref()
        {
            let sorafs_node = sorafs_node
                .as_ref()
                .expect("reputation runtime is disabled during emergency Fast startup");
            let trust_policy = sorafs_node.reputation_trust_policy().ok_or_else(|| {
                Report::new(StartError::StartTorii).attach(
                    "enabled committed SoraFS reputation runtime requires the configured canonical reputation trust policy",
                )
            })?;
            let prepared_archive = prepared_sorafs_reputation_archive.as_ref().ok_or_else(|| {
                Report::new(StartError::StartTorii).attach(
                    "enabled committed SoraFS reputation runtime has no daemon-owned finalized archive installed in Sumeragi",
                )
            })?;
            let reputation_archive_activation = prepared_archive.activation().clone();
            let reputation_archive_active = reputation_archive_activation
                .activation_ready()
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "daemon-owned finalized reputation archive activation gate failed before adapter construction: {error}"
                    ))
                })?;
            let query_qualification =
                sorafs_reputation_runtime::finalized_query_qualification_v1(
                    reputation_config,
                    &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                    trust_policy.as_ref(),
                )
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to derive the daemon-owned finalized reputation query qualification: {error:#}"
                    ))
                })?;
            let finalized_query: Arc<
                dyn sorafs_node::reputation::runtime::ReputationFinalizedQueryV1,
            > = Arc::new(
                sorafs_reputation_finalized_query::ArchivedReputationFinalizedQueryV1::try_new(
                    reputation_config.finalized_query_handle.clone(),
                    query_qualification,
                    Arc::clone(prepared_archive.archive()),
                )
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to construct the daemon-owned finalized reputation query adapter: {error:#}"
                    ))
                })?,
            );
            let journal_transaction_submitter: Arc<
                dyn sorafs_node::reputation::runtime::ReputationJournalTransactionSubmitterV1,
            > = sorafs_reputation_journal_transaction_submitter_override.ok_or_else(|| {
                Report::new(StartError::StartTorii).attach(
                    "enabled committed SoraFS reputation runtime requires an injected authenticated journal-transaction submitter; adapting the validator node key is forbidden",
                )
            })?;
            let retention_control: Option<
                Arc<
                    dyn sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlV1,
                >,
            > = prepared_archive.retention_controller().map(|control| {
                let control: Arc<
                    dyn sorafs_reputation_finalized_query::ReputationFinalizedArchiveRetentionControlV1,
                > = Arc::new(control);
                control
            });
            let dependencies = sorafs_reputation_runtime::ReputationRuntimeDependenciesV1::require(
                Some(Arc::clone(&finalized_query)),
                sorafs_reputation_journal_checkpoint_provider,
                Some(journal_transaction_submitter),
                sorafs_reputation_threshold_signer,
                sorafs_reputation_governance_dag,
                retention_control,
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "enabled committed SoraFS reputation runtime has incomplete runtime-only dependencies: {error:#}"
                ))
            })?;
            let (handle, child) = if reputation_archive_active {
                sorafs_reputation_runtime::start(
                    reputation_config,
                    &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                    trust_policy.as_ref(),
                    dependencies,
                    supervisor.shutdown_signal(),
                )
            } else {
                let activation_probe: sorafs_reputation_runtime::ReputationRuntimeActivationProbeV1 =
                    Arc::new(move || {
                        reputation_archive_activation
                            .activation_ready()
                            .map_err(eyre::Report::new)
                    });
                sorafs_reputation_runtime::start_deferred(
                    reputation_config,
                    &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                    trust_policy.as_ref(),
                    dependencies,
                    activation_probe,
                    supervisor.shutdown_signal(),
                )
            }
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to initialise committed SoraFS reputation runtime: {error:#}"
                ))
            })?;
            supervisor.monitor(child);
            if let Some(scanner_config) = sorafs_reserve_transparency_config.as_ref() {
                let child = sorafs_reserve_transparency_runtime::start(
                    scanner_config,
                    &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                    query_qualification,
                    finalized_query,
                    Arc::clone(&state),
                    sorafs_node::NodeHandle::clone(sorafs_node),
                    supervisor.shutdown_signal(),
                )
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to initialise finalized reserve transparency scanner: {error:#}"
                    ))
                })?;
                supervisor.monitor(child);
            }
            Some(handle)
        } else {
            if sorafs_reserve_transparency_config.is_some() {
                return Err(Report::new(StartError::StartTorii).attach(
                    "enabled finalized reserve transparency scanner requires the committed reputation runtime and immutable finalized archive",
                ));
            }
            None
        };
        if let (Some(reputation_runtime), Some(reputation_config)) = (
            sorafs_reputation_runtime.as_ref(),
            sorafs_reputation_config.as_ref(),
        ) {
            let sorafs_node = sorafs_node
                .as_ref()
                .expect("reputation runtime is disabled during emergency Fast startup");
            let admission: Arc<
                dyn sorafs_node::reputation::runtime::PorTerminalReputationAdmissionV1,
            > = Arc::new(reputation_runtime.clone());
            let child = if sorafs_node.config().por_replay_archive_policy().is_some() {
                sorafs_por_replay_archive_runtime::start(
                    sorafs_node::NodeHandle::clone(sorafs_node),
                    admission,
                    supervisor.shutdown_signal(),
                )
            } else {
                // Reuse the validated native page-item bound as the maximum
                // number of retained PoR terminals admitted by one reputation
                // worker tick. Replay archival is independent and optional.
                sorafs_por_replay_archive_runtime::start_reputation_reconciliation(
                    sorafs_node::NodeHandle::clone(sorafs_node),
                    admission,
                    reputation_config.poll_interval,
                    reputation_config.page_items,
                    supervisor.shutdown_signal(),
                )
            }
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to initialise finalized PoR reputation worker: {error}"
                ))
            })?;
            supervisor.monitor(child);
        } else if sorafs_node
            .as_ref()
            .is_some_and(|node| node.config().por_replay_archive_policy().is_some())
        {
            return Err(Report::new(StartError::StartTorii).attach(
                "enabled finalized PoR replay archival requires the committed reputation runtime",
            ));
        }
        let (sorafs_stream_token_gateway_admission, stream_token_reputation_delivery) =
            sorafs_stream_token_gateway_runtime.map_or((None, None), |runtime| {
                (Some(runtime.provider), Some(runtime.reputation))
            });
        let sorafs_stream_token_admission_capture = if emergency_fast {
            None
        } else {
            sorafs_stream_token_gateway_runtime::prepare_capture(
                &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                &config.torii.sorafs_storage.stream_tokens,
                config
                    .torii
                    .sorafs_gateway
                    .compliance
                    .as_ref()
                    .map(|compliance| compliance.gateway_id.as_str()),
                sorafs_stream_token_gateway_admission,
                stream_token_reputation_delivery,
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to initialise qualified stream-token gateway admission: {error:#}"
                ))
            })?
        };
        if let Some(capture) = sorafs_stream_token_admission_capture.as_ref() {
            let poll_interval = Duration::from_millis(
                config
                    .torii
                    .sorafs_storage
                    .stream_tokens
                    .admission_reconcile_interval_ms,
            );
            let child = sorafs_stream_token_gateway_runtime::start_reconciler(
                Arc::clone(capture),
                poll_interval,
                supervisor.shutdown_signal(),
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to supervise stream-token gateway reconciliation: {error:#}"
                ))
            })?;
            supervisor.monitor(child);
        }
        let sorafs_hedging_billing_runtime = if let Some(hedging_billing_config) =
            sorafs_hedging_billing_config
        {
            let sorafs_node = sorafs_node
                .as_ref()
                .expect("hedging/billing runtime is disabled during emergency Fast startup");
            let feed_policy = sorafs_node
                .hedging_feed_trust_policy()
                .ok_or_else(|| {
                    Report::new(StartError::StartTorii).attach(
                        "enabled committed SoraFS hedging/billing runtime requires the configured canonical hedging-feed trust policy",
                    )
                })?;
            let service_policy = sorafs_node::load_hedging_billing_service_policy(
                &hedging_billing_config.service_policy_path,
                hedging_billing_config.service_policy_digest,
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to load committed SoraFS hedging/billing service policy: {error}"
                ))
            })?;
            let dependencies =
                sorafs_hedging_billing_runtime::HedgingBillingRuntimeDependenciesV1::require(
                    sorafs_hedging_billing_finalized_query,
                    sorafs_hedging_billing_journal_verifier,
                    sorafs_billing_statement_signer,
                    sorafs_billing_statement_publisher,
                    sorafs_billing_acknowledgement_authority,
                    sorafs_hedging_billing_epoch_witness_store,
                )
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "enabled committed SoraFS hedging/billing runtime has incomplete runtime-only dependencies: {error:#}"
                    ))
                })?;
            let (handle, child) = sorafs_hedging_billing_runtime::start(
                hedging_billing_config,
                &NetworkId::from_genesis_hash(config.genesis.expected_hash),
                service_policy,
                &feed_policy,
                dependencies,
                supervisor.shutdown_signal(),
            )
            .map_err(|error| {
                Report::new(StartError::StartTorii).attach(format!(
                    "failed to initialise committed SoraFS hedging/billing runtime: {error:#}"
                ))
            })?;
            supervisor.monitor(child);
            Some(handle)
        } else {
            None
        };
        let sorafs_hedging_billing_torii_runtime: Option<
            Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingRuntimeApiV1>,
        > = sorafs_hedging_billing_runtime.as_ref().map(|runtime| {
            let runtime: Arc<dyn sorafs_node::hedging_billing_service::HedgingBillingRuntimeApiV1> =
                Arc::new(runtime.clone());
            runtime
        });
        let soracloud_runtime = if emergency_fast {
            iroha_logger::warn!(
                "emergency Fast startup skipped Soracloud journal validation, filesystem reconciliation, cache scans, and mutation workers until a Strict restart"
            );
            None
        } else {
            let runtime_manager = prepared_soracloud_runtime
                .expect("normal startup qualified the same manager before consensus")
                .with_sorafs_node(sorafs_node::NodeHandle::clone(
                    sorafs_node
                        .as_ref()
                        .expect("Soracloud is disabled during emergency Fast startup"),
                ))
                .with_remote_stream_token_operator_from_config(&config);
            let runtime_manager = if let Some((store, qualified_manifest_digests)) =
                soracloud_operator_preseed_store
            {
                runtime_manager
                    .with_operator_preseed_store(store, qualified_manifest_digests)
                    .map_err(|error| {
                        Report::new(StartError::StartTorii).attach(format!(
                            "failed to attach qualified Inrou operator-preseed store: {error:#}"
                        ))
                    })?
            } else {
                runtime_manager
            };
            let runtime_manager = if let Some(signer) = soracloud_runtime_mutation_signer {
                let runtime_mutation_sink = QueuedSoracloudRuntimeMutationSink::new(
                    Arc::clone(&queue),
                    Arc::clone(&state),
                    signer,
                    config.soracloud_runtime.submission.clone(),
                );
                let runtime_mutation_sink = Arc::new(runtime_mutation_sink.map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to construct qualified Soracloud runtime mutation sink: {error:#}"
                    ))
                })?);
                runtime_manager.with_mutation_sink(runtime_mutation_sink)
            } else {
                runtime_manager
            };
            let runtime_manager = if let Some(cache) = shared_sorafs_cache.clone() {
                runtime_manager.with_sorafs_provider_cache(cache)
            } else {
                runtime_manager
            };
            let (runtime, child) = runtime_manager
                .start(supervisor.shutdown_signal())
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to initialise embedded Soracloud runtime manager: {error:#}"
                    ))
                })?;
            state.set_soracloud_runtime(Some(Arc::new(runtime.clone())));
            supervisor.monitor(child);
            Some(runtime)
        };
        // The relay only receives the authenticated replayed State. Emergency inspection
        // cannot sign or dispatch AMX carriers. Invalid explicit custody fails activation.
        if !emergency_fast {
            let children = amx_relay::start(
                Arc::clone(&state),
                config.amx_relay.clone(),
                supervisor.shutdown_signal(),
            )
            .map_err(|error| Report::new(StartError::StartAmxRelay).attach(error.to_string()))?;
            for child in children {
                supervisor.monitor(child);
            }
        }
        // The SCCP keeper is a supervised task of its own and never aborts the node: its
        // public RPC delays neither block production nor any other task.
        #[cfg(unix)]
        if !emergency_fast
            && let Some(child) = sccp_keeper::start(
                Arc::clone(&state),
                Arc::clone(&queue),
                &PeerId::new(config.common.key_pair.public_key().clone()),
                &config.sccp.keeper,
                config.sccp.light_client_keeper.clone(),
                supervisor.shutdown_signal(),
            )
        {
            supervisor.monitor(child);
        }
        ensure_operator_node_key_allowlisted(&mut config);
        let (kiso, child) = KisoHandle::start(config.clone());
        supervisor.monitor(child);
        // Normal startup registers runtime update channels before Torii exposes the configuration
        // update endpoint. Fast never exposes that endpoint, so it also leaves
        // these mutable-runtime channels and their relay task absent.
        let config_update_receivers = if emergency_fast {
            None
        } else {
            Some(ConfigUpdateReceivers {
                log_level: kiso.subscribe_on_logger_updates().await.map_err(|error| {
                    Report::new(StartError::StartTorii)
                        .attach(format!("failed to subscribe to logger updates: {error}"))
                })?,
                acl: kiso
                    .subscribe_on_network_acl_updates()
                    .await
                    .map_err(|error| {
                        Report::new(StartError::StartTorii).attach(format!(
                            "failed to subscribe to network ACL updates: {error}"
                        ))
                    })?,
                handshake: kiso
                    .register_soranet_handshake_runtime_applier()
                    .await
                    .map_err(|error| {
                        Report::new(StartError::StartTorii).attach(format!(
                            "failed to register SoraNet handshake runtime applier: {error}"
                        ))
                    })?,
            })
        };
        let receipt_signer = torii_receipt_signer_or_derived(
            config.torii.receipt_signer.clone(),
            &config.common.key_pair,
        )
        .map_err(|err| {
            Report::new(StartError::StartTorii)
                .attach(format!("failed to derive Torii receipt signer: {err}"))
        })?;
        let (vpn_relay_trust, vpn_operator_signer) = if !emergency_fast
            && config.network.soranet_vpn.enabled
        {
            let vpn = &config.network.soranet_vpn;
            let operator_signer = vpn.operator_key_pair.clone().ok_or_else(|| {
                Report::new(StartError::StartTorii)
                    .attach("VPN operator signer missing after configuration validation")
            })?;
            let snapshot_path = vpn.guard_directory_path.as_ref().ok_or_else(|| {
                Report::new(StartError::StartTorii)
                    .attach("VPN guard directory path missing after configuration validation")
            })?;
            let snapshot =
                iroha_crypto::soranet::directory::read_guard_directory_snapshot_file(snapshot_path)
                    .map_err(|error| {
                        Report::new(StartError::StartTorii).attach(format!(
                            "failed to read VPN guard directory {}: {error}",
                            snapshot_path.display()
                        ))
                    })?;
            let expected_digest = vpn.guard_directory_digest.ok_or_else(|| {
                Report::new(StartError::StartTorii)
                    .attach("VPN guard directory digest missing after configuration validation")
            })?;
            let relay_id = vpn.relay_id.ok_or_else(|| {
                Report::new(StartError::StartTorii)
                    .attach("VPN relay identity missing after configuration validation")
            })?;
            let at_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| {
                    Report::new(StartError::StartTorii)
                        .attach(format!("system clock precedes Unix epoch: {error}"))
                })?
                .as_secs()
                .try_into()
                .map_err(|_| {
                    Report::new(StartError::StartTorii).attach("current Unix time exceeds i64::MAX")
                })?;
            let trust = iroha_torii::VpnRelayTrust::from_guard_directory_at(
                &snapshot,
                expected_digest,
                relay_id,
                at_unix,
            )
            .map_err(|error| Report::new(StartError::StartTorii).attach(error))?;
            (Some(trust), Some(operator_signer))
        } else {
            (None, None)
        };
        let musubi_publication_context = sorafs_node.as_ref().map(|sorafs_node| {
            musubi_publication_service::MusubiPublicationPrivateServiceContextV1::new(
                NetworkId::from_genesis_hash(config.genesis.expected_hash),
                Arc::clone(&state),
                Arc::clone(&queue),
                sorafs_node::NodeHandle::clone(sorafs_node),
            )
            .with_native_provider_attestation_inventory(
                native_provider_attestation_inventory.clone(),
            )
        });
        let musubi_publication_factory =
            musubi_publication_service::stock_installation::select_factory(
                &config.musubi_publication,
                musubi_publication_context.as_ref(),
                shared_sorafs_cache.clone(),
                musubi_publication_factory,
                emergency_fast,
            )
            .map_err(|error| Report::new(StartError::StartTorii).attach(error))?;
        let private_settlement_availability_signer = state
            .nexus_snapshot()
            .atomic_private_settlement
            .enabled
            .then(|| {
                iroha_core::private_settlement::PrivateSettlementAvailabilitySignerV1::new(
                    config.common.key_pair.clone(),
                )
            })
            .transpose()
            .map_err(|error| Report::new(StartError::StartTorii).attach(error))?
            .map(Arc::new);
        let private_settlement_phase_signer = state
            .nexus_snapshot()
            .atomic_private_settlement
            .enabled
            .then(|| {
                iroha_core::private_settlement::PrivateSettlementPhaseSignerV1::new(
                    config.common.key_pair.clone(),
                )
            })
            .transpose()
            .map_err(|error| Report::new(StartError::StartTorii).attach(error))?
            .map(Arc::new);
        // Keep the late by-value builder scratch in a separate synchronous call frame
        // instead of the activation poll; no State observation or startup stage moves.
        #[allow(clippy::redundant_closure_call)]
        let runtime_deps = (|| {
        let runtime_deps = iroha_torii::ToriiRuntimeDeps::new(build_identity, torii_telemetry)
            .with_parliament_tle_release_coordinator(parliament_tle_release_coordinator)
            .with_torii_proxy_bridge_signer(config.common.key_pair.clone())
            .with_vpn_relay_trust(vpn_relay_trust);
        let runtime_deps = if let Some(signer) = private_settlement_availability_signer {
            runtime_deps.with_private_settlement_availability_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signer) = private_settlement_phase_signer {
            runtime_deps.with_private_settlement_phase_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(inventory) = native_provider_attestation_inventory.as_ref() {
            runtime_deps.with_sorafs_provider_attestation_inventory(Arc::clone(inventory))
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(sorafs_node) = sorafs_node {
            runtime_deps.with_sorafs_node(sorafs_node)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(soracloud_runtime) = soracloud_runtime.as_ref() {
            runtime_deps.with_soracloud_runtime(Arc::new(soracloud_runtime.clone()))
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signer) = vpn_operator_signer {
            runtime_deps.with_vpn_operator_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(registry) = bootle_lantern_issuance_provider_registry {
            runtime_deps.with_bootle_lantern_issuance_provider_registry(registry)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(runtime) = sorafs_reputation_runtime.as_ref() {
            let reader: Arc<dyn sorafs_node::reputation::runtime::ReputationCommittedReadApiV1> =
                Arc::new(ReadyReputationCommittedReaderV1 {
                    runtime: runtime.clone(),
                });
            runtime_deps.with_sorafs_reputation_committed_reader(reader)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signer) = sorafs_proof_outcome_signer {
            runtime_deps.with_sorafs_proof_outcome_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signer) = sorafs_repair_transaction_signer {
            runtime_deps.with_sorafs_repair_transaction_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signer) = sorafs_reserve_transaction_signer {
            runtime_deps.with_sorafs_reserve_transaction_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signer) = sorafs_orderbook_transaction_signer {
            runtime_deps.with_sorafs_orderbook_transaction_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signer) = sorafs_moderation_transaction_signer {
            runtime_deps.with_sorafs_moderation_transaction_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(client) = sorafs_stream_token_signer_client {
            runtime_deps.with_sorafs_stream_token_signer_client(client)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(observer) = sorafs_stream_token_state_observer {
            runtime_deps.with_sorafs_stream_token_state_observer(observer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(anchor) = sorafs_stream_token_approved_anchor {
            runtime_deps.with_sorafs_stream_token_approved_anchor(anchor)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(capture) = sorafs_stream_token_admission_capture {
            runtime_deps.with_sorafs_stream_token_admission_capture(capture)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(boundary) = sorafs_moderation_settlement_handoff {
            runtime_deps.with_sorafs_moderation_settlement_handoff(boundary)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(boundary) = sorafs_moderation_publication_handoff {
            runtime_deps.with_sorafs_moderation_publication_handoff(boundary)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(boundary) = sorafs_moderation_panel_notification {
            runtime_deps.with_sorafs_moderation_panel_notification(boundary)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(archive) = sorafs_moderation_panel_notification_archive {
            runtime_deps.with_sorafs_moderation_panel_notification_archive(archive)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(checkpoint_store) = sorafs_moderation_checkpoint_store {
            runtime_deps.with_sorafs_moderation_checkpoint_store(checkpoint_store)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(runtime) = sorafs_appeal_finance_checkpoint_runtime {
            runtime_deps.with_sorafs_appeal_finance_checkpoint_runtime(runtime)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(boundary) = sorafs_evidence_viewer_webauthn {
            runtime_deps.with_sorafs_evidence_viewer_webauthn(boundary)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(boundary) = sorafs_evidence_viewer_grants {
            runtime_deps.with_sorafs_evidence_viewer_grants(boundary)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signer) = sorafs_evidence_viewer_receipt_signer {
            runtime_deps.with_sorafs_evidence_viewer_receipt_signer(signer)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(boundary) = sorafs_evidence_viewer_erasure {
            runtime_deps.with_sorafs_evidence_viewer_erasure(boundary)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(checkpoint_store) = sorafs_evidence_viewer_checkpoint_store {
            runtime_deps.with_sorafs_evidence_viewer_checkpoint_store(checkpoint_store)
        } else {
            runtime_deps
        };
        let runtime_deps =
            if let Some(compaction_archive) = sorafs_evidence_viewer_compaction_archive {
                runtime_deps.with_sorafs_evidence_viewer_compaction_archive(compaction_archive)
            } else {
                runtime_deps
            };
        let runtime_deps = if let Some(publisher) = sorafs_evidence_viewer_transparency_publisher {
            runtime_deps.with_sorafs_evidence_viewer_transparency_publisher(publisher)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(runtime) = sorafs_pop_credentials {
            runtime_deps.with_sorafs_pop_credentials(runtime)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(cache) = shared_sorafs_cache {
            runtime_deps.with_sorafs_cache(cache)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(key_wrapper) = moderation_quarantine_key_wrapper {
            runtime_deps.with_sorafs_moderation_quarantine_key_wrapper(key_wrapper)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(client) = sorafs_gateway_acme_client {
            runtime_deps.with_sorafs_gateway_acme_client(client)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(transport) = sorafs_gateway_compliance_feed_transport {
            runtime_deps.with_sorafs_gateway_compliance_feed_transport(transport)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(signers) = sorafs_appeal_finance_runtime_signers {
            runtime_deps.with_sorafs_appeal_finance_runtime_signers(signers)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(roles) = sorafs_potr_runtime_signer_roles {
            runtime_deps.with_sorafs_potr_runtime_signer_roles(roles)
        } else {
            runtime_deps
        };
        let runtime_deps = if let Some(runtime) = sorafs_hedging_billing_torii_runtime {
            runtime_deps.with_sorafs_hedging_billing_runtime(runtime)
        } else {
            runtime_deps
        };
        runtime_deps
        })();
        let queue_backpressure = queue.backpressure_handle();
        // Start proof lanes before Torii begins accepting submissions so one-time GPU setup happens
        // during node startup instead of the first hot-path transaction burst.
        if !emergency_fast {
            // The diagnostic worker uses node-local trace resources, independently
            // of the committed proof validity policy.
            if let Some((_h, child)) = iroha_core::pipeline::zk_lane::start(&config.zk.trace) {
                supervisor.monitor(Child::new(child, OnShutdown::Wait(Duration::from_secs(1))));
            }
            if let Some((_h, child)) =
                iroha_core::fastpq::lane::start_with_backpressure_and_shutdown(
                    &config.zk.fastpq,
                    Some(queue_backpressure),
                    Some(kura.clone()),
                    supervisor.shutdown_signal(),
                )
            {
                supervisor.monitor(Child::new(child, OnShutdown::Wait(Duration::from_secs(1))));
            }
        }
        let online_peers_provider = include!("main/online_peers_provider.rs");
        let torii = Torii::new_with_handle(
            config.common.chain.clone(),
            NetworkId::from_genesis_hash(config.genesis.expected_hash),
            kiso.clone(),
            config.torii,
            queue,
            events_sender,
            live_query_store,
            kura.clone(),
            state.clone(),
            receipt_signer,
            online_peers_provider,
            sumeragi.clone(),
            runtime_deps,
        )
        .map_err(|error| {
            Report::new(StartError::StartTorii)
                .attach(format!("failed to construct Torii: {error}"))
        })?;
        let torii = if emergency_fast {
            torii
        } else {
            torii.with_p2p(network.clone())
        };
        let torii = torii.with_local_peer_id(config.common.peer.id.clone());
        let torii_run = torii.start(supervisor.shutdown_signal());
        let shutdown_on_failure = supervisor.shutdown_signal();
        supervisor.monitor(Child::new(
            tokio::spawn(async move {
                if let Err(err) = Box::pin(torii_run).await {
                    iroha_logger::error!(?err, "Torii failed to terminate gracefully");
                    shutdown_on_failure.send();
                    std::process::exit(1);
                } else {
                    iroha_logger::debug!("Torii exited normally");
                }
            }),
            OnShutdown::Wait(Duration::from_secs(5)),
        ));
        let network_relay_shutdown = supervisor.shutdown_signal();
        supervisor.monitor(task::spawn(
            network_relay::NetworkRelay {
                tx_gossiper,
                peers_gossiper,
                network: network.clone(),
                streaming: streaming.clone(),
                low_priority_ingress: network_relay::LowPriorityIngressLimiter::from_config(
                    &config.network,
                ),
                emergency_fast,
            }
            .run(network_relay_shutdown),
        ));
        // Observer nodes are configured with `NodeRole::Observer`; Sumeragi suppresses
        // local consensus emissions in that case, so observers follow the chain and
        // serve queries without proposing or voting. Validators retain the full duties.
        if let Some(config_update_receivers) = config_update_receivers {
            let net_for_relay = network.clone();
            // The relay retains `kiso`, so its update senders cannot close through ordinary
            // handle loss. Any pre-shutdown return means the supervised configuration
            // authority failed; restarting only this relay would preserve stale ACL or
            // handshake policy and is therefore deliberately not recoverable.
            supervisor.monitor(tokio::task::spawn(async move {
                if let Err(err) =
                    config_updates_relay(kiso, logger, net_for_relay, config_update_receivers).await
                {
                    iroha_logger::error!(?err, "Config updates relay exited");
                }
            }));
        }
        supervisor
            .setup_shutdown_on_os_signals()
            .change_context(StartError::ListenOsSignal)?;
        if !emergency_fast {
            let (_availability, publication_child) = musubi_publication_service::
                build_and_start_injected_musubi_publication_private_service_v1(
                    musubi_publication_factory,
                    musubi_publication_context
                        .expect("private Musubi publication is disabled during emergency Fast startup"),
                    supervisor.shutdown_signal(),
                )
                .map_err(|error| {
                    Report::new(StartError::StartTorii).attach(format!(
                        "failed to assemble private Musubi publication service: {error}"
                    ))
                })?;
            if let Some(child) = publication_child {
                supervisor.monitor(child);
            }
        }
        Ok(Self {
                kura,
                state,
                soracloud_runtime,
                streaming: streaming.clone(),
                network: network.clone(),
                sorafs_reputation_runtime,
                sorafs_hedging_billing_runtime,
                sorafs_provider_ingest_runtime,
                sorafs_provider_ingest_finalized_query,
                sorafs_provider_ingest_completed_musubi_capture,
        })
        }).await;
        match result {
            Ok(node) => {
                let StartupLifetime {
                    nts_reservation,
                    kura: original_kura,
                    state: original_state,
                } = lifetime;
                // Finalize NTS ownership only after every fallible startup preflight has
                // succeeded. Otherwise an early return would detach a task and retain
                // its process-singleton ownership across an in-process retry. Fast is a
                // bounded recovery surface, so it holds policy ownership but leaves the
                // sampler inert.
                let nts_child = if config_emergency_fast {
                    iroha_core::time::hold_fallback_reserved(
                        nts_reservation,
                        supervisor.shutdown_signal(),
                    )
                } else {
                    iroha_core::time::start_reserved(
                        node.network.clone(),
                        nts_reservation,
                        supervisor.shutdown_signal(),
                    )
                };
                supervisor.monitor(nts_child);
                supervisor.shutdown_on_external_signal(shutdown_signal);
                drop((original_state, original_kura));
                Ok((node, async move {
                    supervisor.start().await?;
                    iroha_logger::info!("Iroha shutdown normally");
                    Ok(())
                }))
            }
            Err(error) => {
                supervisor.shutdown_signal().send();
                let cleanup = supervisor.start().await;
                drop(lifetime);
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        Err(error.attach(format!("startup activation cleanup failed: {cleanup:?}")))
                    }
                }
            }
        }
    }
    /// Read-only handle to the world state view.
    pub fn state(&self) -> &Arc<State> {
        &self.state
    }
    /// Access to the block storage handle.
    pub fn kura(&self) -> &Arc<Kura> {
        &self.kura
    }
    /// Access the daemon-owned archive-only provider-ingest finalized query.
    pub fn sorafs_provider_ingest_finalized_query(
        &self,
    ) -> Option<&Arc<sorafs_provider_ingest_finalized_query::ArchivedProviderIngestFinalizedLedgerV1>>
    {
        self.sorafs_provider_ingest_finalized_query.as_ref()
    }
    /// Access the embedded Soracloud runtime-manager handle.
    pub fn soracloud_runtime(&self) -> Option<&SoracloudRuntimeManagerHandle> {
        self.soracloud_runtime.as_ref()
    }
    /// Streaming handle used for Torii and telemetry ingress.
    pub fn streaming(&self) -> iroha_core::streaming::StreamingHandle {
        self.streaming.clone()
    }
    /// Access the supervised committed `SoraFS` reputation status/metrics handle.
    #[must_use]
    pub fn sorafs_reputation_runtime(
        &self,
    ) -> Option<&sorafs_reputation_runtime::ReputationRuntimeHandleV1> {
        self.sorafs_reputation_runtime.as_ref()
    }
    /// Access the supervised committed `SoraFS` hedging/billing status and metrics handle.
    #[must_use]
    pub fn sorafs_hedging_billing_runtime(
        &self,
    ) -> Option<&sorafs_hedging_billing_runtime::HedgingBillingRuntimeHandleV1> {
        self.sorafs_hedging_billing_runtime.as_ref()
    }
    /// Access the supervised finalized-ledger `SoraFS` provider-ingest status and metrics handle.
    #[must_use]
    pub fn sorafs_provider_ingest_runtime(
        &self,
    ) -> Option<&sorafs_provider_ingest_runtime::ProviderIngestRuntimeHandleV1> {
        self.sorafs_provider_ingest_runtime.as_ref()
    }
    /// Construct a manifest publisher for the active network.
    pub fn manifest_publisher(&self) -> ManifestPublisher<IrohaNetwork> {
        ManifestPublisher::new(self.streaming.clone(), self.network.clone())
    }
}
#[cfg(feature = "telemetry")]
struct AbortTelemetryTaskOnDrop(tokio::task::AbortHandle);
#[cfg(feature = "telemetry")]
impl Drop for AbortTelemetryTaskOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[cfg(feature = "telemetry")]
fn monitor_optional_telemetry_task(
    supervisor: &mut Supervisor,
    task_name: &'static str,
    mut handle: tokio::task::JoinHandle<()>,
) {
    let shutdown = supervisor.shutdown_signal();
    let abort_on_drop = AbortTelemetryTaskOnDrop(handle.abort_handle());
    supervisor.monitor(tokio::spawn(async move {
        let _abort_on_drop = abort_on_drop;
        tokio::select! {
            result = &mut handle => {
                match result {
                    Ok(()) => iroha_logger::warn!(task = task_name, "Optional telemetry task exited"),
                    Err(error) => {
                        iroha_logger::error!(task = task_name, %error, "Optional telemetry task failed")
                    }
                }
                shutdown.receive().await;
            }
            () = shutdown.receive() => {
                handle.abort();
                let _ = handle.await;
            }
        }
    }));
}
#[cfg(feature = "telemetry")]
async fn start_telemetry(
    logger: &LoggerHandle,
    config: &Config,
    telemetry: &iroha_core::telemetry::Telemetry,
    supervisor: &mut Supervisor,
) {
    #[cfg(not(feature = "telegram-alerts"))]
    let _ = telemetry;
    let telemetry_profile = config.telemetry_profile;
    if !telemetry_profile.metrics_enabled() {
        iroha_logger::info!(
            ?telemetry_profile,
            "Telemetry metrics disabled by profile; skipping sinks",
        );
        return;
    }
    #[cfg(feature = "dev-telemetry")]
    {
        if telemetry_profile.developer_outputs_enabled() {
            if let Some(out_file) = &config.dev_telemetry.out_file {
                match logger
                    .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Future)
                    .await
                {
                    Ok(receiver) => match iroha_telemetry::dev::start_file_output(
                        out_file.resolve_relative_path(),
                        config.telemetry_integrity.clone(),
                        receiver,
                    )
                    .await
                    {
                        Ok(handle) => {
                            monitor_optional_telemetry_task(supervisor, "developer", handle)
                        }
                        Err(error) => {
                            iroha_logger::warn!(%error, "Failed to start developer telemetry")
                        }
                    },
                    Err(error) => {
                        iroha_logger::warn!(%error, "Failed to subscribe developer telemetry")
                    }
                }
            }
        } else {
            iroha_logger::debug!(
                ?telemetry_profile,
                "Developer telemetry outputs disabled by profile",
            );
        }
    }
    if let Some(telemetry_cfg) = &config.telemetry {
        match logger
            .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Regular)
            .await
        {
            Ok(receiver) => match iroha_telemetry::ws::start(
                telemetry_cfg.clone(),
                config.telemetry_integrity.clone(),
                receiver,
            ) {
                Ok(handle) => monitor_optional_telemetry_task(supervisor, "websocket", handle),
                Err(error) => iroha_logger::warn!(%error, "Failed to start telemetry exporter"),
            },
            Err(error) => iroha_logger::warn!(%error, "Failed to subscribe telemetry exporter"),
        }
        #[cfg(feature = "telegram-alerts")]
        if telemetry_profile.developer_outputs_enabled()
            && telemetry_cfg.telegram_bot_key.is_some()
            && telemetry_cfg.telegram_chat_id.is_some()
        {
            let chain_id_str = config.common.chain.to_string();
            let node_name = config.common.peer.id.to_string();
            let metrics_telemetry = telemetry.clone();
            match logger
                .subscribe_on_telemetry(iroha_logger::telemetry::Channel::Regular)
                .await
            {
                Ok(receiver) => match iroha_telemetry::telegram::start(
                    telemetry_cfg.clone(),
                    node_name,
                    Some(chain_id_str),
                    move || {
                        let telemetry = metrics_telemetry.clone();
                        async move {
                            telemetry
                                .metrics_fresh_checked()
                                .await
                                .ok()
                                .map(iroha_telemetry::telegram::MetricsSnapshot::from_metrics)
                        }
                    },
                    receiver,
                ) {
                    Ok(handle) => monitor_optional_telemetry_task(supervisor, "telegram", handle),
                    Err(error) => iroha_logger::warn!(%error, "Failed to start Telegram alerts"),
                },
                Err(error) => {
                    iroha_logger::warn!(%error, "Failed to subscribe Telegram alerts")
                }
            }
        }
        iroha_logger::info!("Telemetry sink startup completed");
    } else {
        iroha_logger::info!("Telemetry not started due to absent configuration");
    }
}
/// Relays local configuration-actor updates to local runtime components.
///
/// Security-sensitive handshake policy is never accepted from, or propagated
/// to, remote peers. Every node derives it exclusively from its own
/// operator-controlled configuration.
struct ConfigUpdateReceivers {
    log_level: tokio::sync::watch::Receiver<iroha_config::parameters::actual::Logger>,
    acl: tokio::sync::watch::Receiver<iroha_torii_shared::configuration::NetworkAcl>,
    handshake: tokio::sync::mpsc::Receiver<SoranetHandshakeApplyRequest>,
}
#[allow(clippy::too_many_lines)]
async fn config_updates_relay(
    _kiso: KisoHandle,
    logger: LoggerHandle,
    network: iroha_core::IrohaNetwork,
    config_update_receivers: ConfigUpdateReceivers,
) -> EyreResult<()> {
    let mut log_level_update = config_update_receivers.log_level;
    let mut acl_update = config_update_receivers.acl;
    let mut handshake_update = config_update_receivers.handshake;
    #[cfg(feature = "telemetry")]
    let confidential_metrics_handle = iroha_telemetry::metrics::global().cloned();
    #[cfg(feature = "telemetry")]
    if let Some(metrics) = confidential_metrics_handle.as_ref() {
        // The confidential verification gas gauges follow the schedule State
        // charges; Core sets them whenever it installs a schedule.
        let digest = ivm::gas::schedule_hash();
        metrics.set_ivm_gas_schedule_hash(digest.as_ref());
    }
    // Handshake proposals are acknowledged only after the network actor accepts
    // the exact candidate. Kiso commits and publishes its snapshot afterward.
    #[cfg(feature = "telemetry")]
    #[allow(clippy::redundant_pub_crate)]
    loop {
        tokio::select! {
            result = log_level_update.changed() => {
                if let Ok(()) = result {
                    let value = log_level_update.borrow_and_update().clone();
                    if let Err(error) = logger.reload_level(value.resolve_filter()).await {
                        iroha_logger::error!("Failed to reload log level: {error}");
                    }
                } else {
                    iroha_logger::debug!("Exiting config updates relay (log level channel closed)");
                    break;
                }
            },
            result = acl_update.changed() => {
                if let Ok(()) = result {
                    let value = acl_update.borrow_and_update().clone();
                    let update = iroha_p2p::network::message::UpdateAcl {
                        allowlist_only: value.allowlist_only.unwrap_or(false),
                        allow_keys: value.allow_keys.clone().unwrap_or_default(),
                        deny_keys: value.deny_keys.clone().unwrap_or_default(),
                        allow_cidrs: value.allow_cidrs.clone().unwrap_or_default(),
                        deny_cidrs: value.deny_cidrs.clone().unwrap_or_default(),
                    };
                    network.update_acl(update);
                } else {
                    iroha_logger::debug!("Exiting config updates relay (ACL channel closed)");
                    break;
                }
            },
            request = handshake_update.recv() => {
                let Some(request) = request else {
                    iroha_logger::debug!("Exiting config updates relay (handshake channel closed)");
                    break;
                };
                let result = network
                    .update_soranet_handshake(request.handshake)
                    .await
                    .map_err(|error| error.to_string());
                let _ = request.respond_to.send(result);
            },
        };
    }
    #[cfg(not(feature = "telemetry"))]
    #[allow(clippy::redundant_pub_crate)]
    loop {
        tokio::select! {
            result = log_level_update.changed() => {
                if let Ok(()) = result {
                    let value = log_level_update.borrow_and_update().clone();
                    if let Err(error) = logger.reload_level(value.resolve_filter()).await {
                        iroha_logger::error!("Failed to reload log level: {error}");
                    }
                } else {
                    iroha_logger::debug!("Exiting config updates relay (log level channel closed)");
                    break;
                }
            },
            result = acl_update.changed() => {
                if let Ok(()) = result {
                    let value = acl_update.borrow_and_update().clone();
                    let update = iroha_p2p::network::message::UpdateAcl {
                        allowlist_only: value.allowlist_only.unwrap_or(false),
                        allow_keys: value.allow_keys.clone().unwrap_or_default(),
                        deny_keys: value.deny_keys.clone().unwrap_or_default(),
                        allow_cidrs: value.allow_cidrs.clone().unwrap_or_default(),
                        deny_cidrs: value.deny_cidrs.clone().unwrap_or_default(),
                    };
                    network.update_acl(update);
                } else {
                    iroha_logger::debug!("Exiting config updates relay (ACL channel closed)");
                    break;
                }
            },
            request = handshake_update.recv() => {
                let Some(request) = request else {
                    iroha_logger::debug!("Exiting config updates relay (handshake channel closed)");
                    break;
                };
                let result = network
                    .update_soranet_handshake(request.handshake)
                    .await
                    .map_err(|error| error.to_string());
                let _ = request.respond_to.send(result);
            },
        };
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedGenesisTrustAnchor {
    public_key: PublicKey,
    consensus_header_hash: HashOf<BlockHeader>,
}
fn load_configured_startup_genesis(
    genesis: Option<GenesisBlock>,
    signed_file: Option<&WithOrigin<PathBuf>>,
) -> ReportResult<Option<GenesisBlock>, StartError> {
    if genesis.is_some() {
        return Ok(genesis);
    }
    let Some(signed_file) = signed_file else {
        return Ok(None);
    };
    read_genesis(&signed_file.resolve_relative_path())
        .attach(signed_file.clone().into_attachment().display_path())
        .change_context(StartError::InitKura)
        .map(Some)
}
impl ResolvedGenesisTrustAnchor {
    fn resolve(
        public_key: &PublicKey,
        configured_hash: HashOf<BlockHeader>,
        local_genesis: Option<&GenesisBlock>,
    ) -> ReportResult<Self, StartError> {
        if let Some(local) = local_genesis.map(|genesis| genesis.0.hash())
            && configured_hash != local
        {
            return Err(Report::new(StartError::InitKura).attach(format!(
                "local signed genesis hash {local} differs from configured genesis.expected_hash {configured_hash}"
            )));
        }
        let anchor = Self {
            public_key: public_key.clone(),
            consensus_header_hash: configured_hash,
        };
        if let Some(local_genesis) = local_genesis {
            anchor.verify(&local_genesis.0)?;
        }
        Ok(anchor)
    }
    fn verify(&self, block: &SignedBlock) -> ReportResult<(), StartError> {
        let embedded_key = genesis_public_key_from_genesis_block(block)?;
        if embedded_key != self.public_key {
            return Err(Report::new(StartError::InitKura).attach(format!(
                "genesis authority `{embedded_key}` does not match configured genesis.public_key `{}`",
                self.public_key
            )));
        }
        let block_hash = block.hash();
        if block_hash != self.consensus_header_hash {
            return Err(Report::new(StartError::InitKura).attach(format!(
                "genesis hash {block_hash} does not match the resolved genesis trust-anchor hash {}",
                self.consensus_header_hash
            )));
        }
        let mut signatures = block.signatures();
        let signature = signatures.next().ok_or_else(|| {
            Report::new(StartError::InitKura)
                .attach("genesis block has no configured-authority signature")
        })?;
        if signature.index() != 0 || signatures.next().is_some() {
            return Err(Report::new(StartError::InitKura)
                .attach("genesis block must have exactly one signature at index 0"));
        }
        signature
            .signature()
            .verify_hash(&self.public_key, block_hash)
            .map_err(|error| {
                Report::new(StartError::InitKura).attach(format!(
                    "genesis block signature does not verify against configured genesis.public_key `{}`: {error}",
                    self.public_key
                ))
            })?;
        Ok(())
    }
}
fn read_stored_genesis_block(
    kura: &Kura,
    block_count: iroha_core::kura::BlockCount,
    execution_budget: &iroha_allocation::AllocationBudget,
) -> ReportResult<Option<iroha_data_model::block::SharedSignedBlock>, StartError> {
    if block_count.0 == 0 {
        return Ok(None);
    }
    let nz = std::num::NonZeroUsize::new(1).expect("nonzero");
    let Some(stored) = kura
        .get_block(nz, execution_budget)
        .map_err(|error| Report::new(error).change_context(StartError::InitKura))?
    else {
        return Err(Report::new(StartError::InitKura)
            .attach("non-empty block store is missing genesis block at height 1"));
    };
    Ok(Some(stored))
}
fn genesis_public_key_from_genesis_block(
    block: &SignedBlock,
) -> ReportResult<PublicKey, StartError> {
    let first = block.external_transactions().next().ok_or_else(|| {
        Report::new(StartError::InitKura).attach("stored genesis block contains no transactions")
    })?;
    let authority = first.authority();
    authority.try_signatory().cloned().ok_or_else(|| {
        Report::new(StartError::InitKura)
            .attach("stored genesis transaction authority is not a single-key account")
    })
}
fn genesis_account(public_key: PublicKey) -> Account {
    let genesis_account_id = AccountId::new(public_key);
    Account::new(genesis_account_id.clone()).build(&genesis_account_id)
}
fn genesis_domain(public_key: PublicKey) -> Domain {
    let genesis_account_id = AccountId::new(public_key);
    Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&genesis_account_id)
}
#[cfg(test)]
mod genesis_key_tests {
    use super::*;
    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_genesis::GenesisBuilder;
    use iroha_model_base::chain::ChainId;
    use std::path::PathBuf;
    fn prepared_genesis_proposal(keypair: &KeyPair) -> GenesisBlock {
        let proposal = complete_test_genesis_builder(GenesisBuilder::new_without_executor(
            ChainId::from("configured-genesis-trust-anchor-test"),
            PathBuf::from("."),
        ))
        .build_raw()
        .expect("build complete prepared genesis manifest")
        .build_and_sign(keypair)
        .expect("build prepared genesis proposal");
        assert!(proposal.0.is_resultless_proposal());
        proposal
    }
    fn prepared_genesis_proposal_with_marker(keypair: &KeyPair, marker: &str) -> GenesisBlock {
        let proposal = complete_test_genesis_builder(
            GenesisBuilder::new_without_executor(
                ChainId::from("configured-genesis-trust-anchor-test"),
                PathBuf::from("."),
            )
            .append_instruction(iroha_data_model::isi::Log::new(
                iroha_data_model::Level::INFO,
                marker.to_owned(),
            )),
        )
        .build_raw()
        .expect("build complete marked prepared genesis manifest")
        .build_and_sign(keypair)
        .expect("build marked prepared genesis proposal");
        assert!(proposal.0.is_resultless_proposal());
        proposal
    }
    fn write_prepared_genesis_proposal(path: &Path, proposal: &GenesisBlock) {
        assert!(proposal.0.is_resultless_proposal());
        let bytes = {
            let _registry_guard = instruction_registry_test_guard();
            init_genesis_instruction_registry();
            proposal
                .0
                .encode_wire()
                .expect("encode prepared genesis proposal")
        };
        fs::write(path, bytes).expect("write prepared genesis proposal");
    }
    #[test]
    fn derives_genesis_pubkey_from_block_authority() {
        let chain = ChainId::from("derive-genesis-pubkey-test");
        let manifest = complete_test_genesis_builder(GenesisBuilder::new_without_executor(
            chain,
            PathBuf::from("."),
        ))
        .build_raw()
        .expect("build complete genesis public-key derivation manifest");
        let keypair = iroha_crypto::KeyPair::random();
        let genesis_block = manifest
            .build_and_sign(&keypair)
            .expect("build genesis block");
        assert!(genesis_block.0.is_resultless_proposal());
        let derived =
            genesis_public_key_from_genesis_block(&genesis_block.0).expect("derive genesis pubkey");
        assert_eq!(&derived, keypair.public_key());
    }
    #[test]
    fn genesis_domain_owner_matches_genesis_authority() {
        let keypair = iroha_crypto::KeyPair::random();
        let expected_owner = AccountId::new(keypair.public_key().clone());
        let domain = genesis_domain(keypair.public_key().clone());
        assert_eq!(domain.owned_by(), &expected_owner);
    }
    #[test]
    fn resolved_genesis_trust_anchor_accepts_matching_block() {
        let keypair = KeyPair::random();
        let genesis = prepared_genesis_proposal(&keypair);
        let anchor = ResolvedGenesisTrustAnchor {
            public_key: keypair.public_key().clone(),
            consensus_header_hash: genesis.0.hash(),
        };
        anchor
            .verify(&genesis.0)
            .expect("matching configured genesis trust anchor should verify");
    }
    #[test]
    fn resolved_genesis_trust_anchor_rejects_wrong_public_key() {
        let signer = KeyPair::random();
        let genesis = prepared_genesis_proposal(&signer);
        let anchor = ResolvedGenesisTrustAnchor {
            public_key: KeyPair::random().public_key().clone(),
            consensus_header_hash: genesis.0.hash(),
        };
        let error = anchor
            .verify(&genesis.0)
            .expect_err("configured public-key mismatch must reject genesis");
        assert!(matches!(error.current_context(), StartError::InitKura));
        assert!(
            format!("{error:?}").contains("does not match configured genesis.public_key"),
            "unexpected mismatch diagnostic: {error:?}"
        );
    }
    // Direct fragment preserves the genesis trust-anchor test path and source order.
    include!("main/resolved_genesis_trust_anchor_wrong_hash_test.rs");
    #[test]
    fn startup_trust_root_requires_local_artifact_to_match_configured_hash() {
        let keypair = KeyPair::random();
        let genesis = prepared_genesis_proposal(&keypair);
        let root = ResolvedGenesisTrustAnchor::resolve(
            keypair.public_key(),
            genesis.0.hash(),
            Some(&genesis),
        )
        .expect("the local signed genesis matches the independently configured hash");
        let anchor = root;
        assert_eq!(anchor.consensus_header_hash, genesis.0.hash());
        anchor.verify(&genesis.0).expect("resolved anchor verifies");
    }
    #[test]
    fn startup_loads_original_configured_genesis() {
        let keypair = KeyPair::random();
        let genesis = prepared_genesis_proposal(&keypair);
        let temp = tempfile::tempdir().expect("temporary directory");
        let path = temp.path().join("genesis.proposal.nrt");
        write_prepared_genesis_proposal(&path, &genesis);
        let proposal_file = WithOrigin::inline(path);
        let loaded = load_configured_startup_genesis(None, Some(&proposal_file))
            .expect("normal startup reads the protected local artifact")
            .expect("normal startup loads a genesis block");
        assert!(loaded.0.is_resultless_proposal());
        assert_eq!(loaded.0.hash(), genesis.0.hash());
    }
    #[test]
    fn startup_rejects_missing_configured_genesis() {
        let temp = tempfile::tempdir().unwrap();
        let missing = WithOrigin::inline(temp.path().join("missing-genesis.nrt"));
        assert!(load_configured_startup_genesis(None, Some(&missing)).is_err());
    }
    #[test]
    fn resolver_rejects_config_and_local_hash_disagreement() {
        let keypair = KeyPair::random();
        let genesis = prepared_genesis_proposal(&keypair);
        let configured_hash =
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xB6; 32]));
        assert_ne!(configured_hash, genesis.0.hash());
        let error = ResolvedGenesisTrustAnchor::resolve(
            keypair.public_key(),
            configured_hash,
            Some(&genesis),
        )
        .expect_err("two exact genesis sources must agree");
        assert!(matches!(error.current_context(), StartError::InitKura));
        assert!(
            format!("{error:?}").contains("differs from configured genesis.expected_hash"),
            "unexpected conflicting-anchor diagnostic: {error:?}"
        );
    }
    #[test]
    fn resolver_accepts_matching_config_and_local_hashes() {
        let keypair = KeyPair::random();
        let genesis = prepared_genesis_proposal(&keypair);
        let root = ResolvedGenesisTrustAnchor::resolve(
            keypair.public_key(),
            genesis.0.hash(),
            Some(&genesis),
        )
        .expect("matching configured and local hashes resolve one exact anchor");
        let anchor = root;
        assert_eq!(anchor.consensus_header_hash, genesis.0.hash());
    }
    #[test]
    fn configured_anchor_rejects_alternate_same_key_same_chain_genesis_with_local_body() {
        let keypair = KeyPair::random();
        let trusted = prepared_genesis_proposal_with_marker(&keypair, "trusted genesis");
        let alternate = prepared_genesis_proposal_with_marker(&keypair, "alternate genesis");
        assert_ne!(trusted.0.hash(), alternate.0.hash());
        let root = ResolvedGenesisTrustAnchor::resolve(
            keypair.public_key(),
            trusted.0.hash(),
            Some(&trusted),
        )
        .expect("the local trusted genesis matches the configured exact anchor");
        let anchor = root;
        let error = anchor
            .verify(&alternate.0)
            .expect_err("same signer and chain must not authorize another genesis instance");
        assert!(matches!(error.current_context(), StartError::InitKura));
        assert!(
            format!("{error:?}").contains("does not match the resolved genesis trust-anchor hash"),
            "unexpected alternate-genesis diagnostic: {error:?}"
        );
    }
    #[test]
    fn configured_hash_anchor_rejects_alternate_same_key_same_chain_genesis() {
        let keypair = KeyPair::random();
        let trusted = prepared_genesis_proposal_with_marker(&keypair, "trusted genesis");
        let alternate = prepared_genesis_proposal_with_marker(&keypair, "alternate genesis");
        assert_ne!(trusted.0.hash(), alternate.0.hash());
        let root =
            ResolvedGenesisTrustAnchor::resolve(keypair.public_key(), trusted.0.hash(), None)
                .expect("configured expected hash resolves an exact anchor");
        let anchor = root;
        let error = anchor
            .verify(&alternate.0)
            .expect_err("the configured hash must reject another genesis from the same signer");
        assert!(matches!(error.current_context(), StartError::InitKura));
        assert!(
            format!("{error:?}").contains("does not match the resolved genesis trust-anchor hash"),
            "unexpected alternate-genesis diagnostic: {error:?}"
        );
    }
}
/// Errors raised while reading configuration and genesis data.
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// Failed to read the selected configuration source.
    ReadConfig,
    /// Configuration contents failed validation.
    ParseConfig,
    /// Failed to load the genesis file.
    ReadGenesis,
    #[cfg(feature = "dev-telemetry")]
    /// Telemetry output path resolved to root or empty.
    TelemetryOutFileIsRootOrEmpty,
    #[cfg(feature = "dev-telemetry")]
    /// Telemetry output path pointed to a directory.
    TelemetryOutFileIsDir,
    /// Telemetry settings request a capability that is disabled or absent from this build.
    InactiveTelemetryConfiguration,
    /// Network and Torii addresses conflict.
    SameNetworkAndToriiAddrs,
    /// Invalid directory path supplied in configuration.
    InvalidDirPath,
    /// Confidential features are disabled for a validator build.
    ConfidentialDisabledForValidator,
    /// Confidential assume-valid was enabled for a validator build.
    ConfidentialAssumeValidForValidator,
    /// Encrypted P2P frame cap exceeds the deterministic runtime buffer limit.
    NetworkFrameSizeExceedsRuntimeLimit {
        /// Configured encrypted-frame cap in bytes.
        configured: usize,
    },
    /// A topic plaintext cap exceeds the payload carried by the encrypted frame cap.
    NetworkTopicFrameSizeExceedsPlaintextLimit {
        /// Canonical configuration path for the topic cap.
        path: &'static str,
        /// Configured topic plaintext cap in bytes.
        configured: usize,
        /// Maximum plaintext bytes carried by the configured encrypted frame cap.
        plaintext_ceiling: usize,
        /// Configured encrypted frame cap from which the plaintext ceiling is derived.
        encrypted_cap: usize,
    },
    /// Failed to bind a configured address.
    CannotBindAddress {
        /// Address that could not be bound.
        addr: SocketAddr,
    },
    /// Joining Sora profile is mandatory but missing.
    SoraProfileRequired,
    /// Embedded `SoraFS` storage was enabled without governed gateway compliance.
    SorafsStorageComplianceRequired,
    /// `SoraFS` gateway automation was enabled while embedded storage was disabled.
    SorafsGatewayRequiresStorage,
}
impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReadConfig => write!(f, "Error occurred while reading configuration sources"),
            Self::ParseConfig => {
                write!(f, "Error occurred while validating configuration integrity")
            }
            Self::ReadGenesis => write!(f, "Error occurred while reading genesis block"),
            #[cfg(feature = "dev-telemetry")]
            Self::TelemetryOutFileIsRootOrEmpty => {
                write!(f, "Telemetry output file path is root or empty")
            }
            #[cfg(feature = "dev-telemetry")]
            Self::TelemetryOutFileIsDir => {
                write!(f, "Telemetry output file path is a directory")
            }
            Self::InactiveTelemetryConfiguration => write!(
                f,
                "Telemetry configuration requests an inactive or unavailable capability"
            ),
            Self::SameNetworkAndToriiAddrs => write!(
                f,
                "Torii and Network addresses are the same, but should be different"
            ),
            Self::InvalidDirPath => write!(f, "Invalid directory path found"),
            Self::ConfidentialDisabledForValidator => write!(
                f,
                "validator nodes must enable confidential verification (`confidential.enabled = true`)"
            ),
            Self::ConfidentialAssumeValidForValidator => write!(
                f,
                "validator nodes cannot enable confidential observer mode (`confidential.assume_valid = false` required)"
            ),
            Self::NetworkFrameSizeExceedsRuntimeLimit { configured } => write!(
                f,
                "network.max_frame_bytes ({configured}) exceeds the deterministic encrypted P2P runtime limit of {} bytes (the wire uses a u32 body-length prefix)",
                iroha_p2p::MAX_ENCRYPTED_FRAME_BYTES,
            ),
            Self::NetworkTopicFrameSizeExceedsPlaintextLimit {
                path,
                configured,
                plaintext_ceiling,
                encrypted_cap,
            } => write!(
                f,
                "{path} ({configured}) exceeds the AEAD-specific plaintext ceiling of {plaintext_ceiling} bytes derived from network.max_frame_bytes ({encrypted_cap})",
            ),
            Self::CannotBindAddress { addr } => {
                write!(f, "Network error: cannot listen to address `{addr}`")
            }
            Self::SoraProfileRequired => {
                write!(
                    f,
                    "Sora Nexus features require `iroha3d --sora`; remove the Sora-only config overrides or rerun with the flag"
                )
            }
            Self::SorafsStorageComplianceRequired => write!(
                f,
                "sorafs.storage.enabled requires the governed sorafs.gateway.compliance controller"
            ),
            Self::SorafsGatewayRequiresStorage => write!(
                f,
                "SoraFS gateway ACME/compliance configuration requires sorafs.storage.enabled"
            ),
        }
    }
}
impl std::error::Error for ConfigError {}
/// Render the IVM scheduler banner line for a given core count.
fn scheduler_banner_line(core_count: usize) -> String {
    let count = core_count.max(1);
    let core_label = if count == 1 { "core" } else { "cores" };
    format!("Using {count} {core_label}")
}
/// Translate FASTPQ Metal-related configuration into overrides understood by the prover.
fn fastpq_metal_overrides_from_config(
    config: &iroha_config::parameters::actual::Fastpq,
) -> MetalOverrides {
    MetalOverrides {
        max_in_flight: config.metal_max_in_flight,
        threadgroup_size: config.metal_threadgroup_width,
        dispatch_trace: config.metal_trace,
        debug_enum: config.metal_debug_enum,
    }
}
/// Apply concurrency settings (IVM scheduler + Rayon) derived from configuration.
fn apply_concurrency_config(concurrency: &iroha_config::parameters::actual::Concurrency) {
    let stack_outcome = ivm::apply_stack_sizes(
        concurrency.scheduler_stack_bytes,
        concurrency.prover_stack_bytes,
    );
    iroha_core::sumeragi::set_sumeragi_stack_size_bytes(concurrency.sumeragi_stack_bytes);
    if stack_outcome.scheduler_clamped || stack_outcome.prover_clamped {
        iroha_logger::warn!(
            requested_scheduler_bytes = stack_outcome.requested_scheduler_bytes,
            requested_prover_bytes = stack_outcome.requested_prover_bytes,
            scheduler_bytes = stack_outcome.scheduler_bytes,
            prover_bytes = stack_outcome.prover_bytes,
            min_stack_bytes = ivm::MIN_STACK_BYTES,
            max_stack_bytes = ivm::MAX_STACK_BYTES,
            "Stack size overrides were clamped to the supported range"
        );
    }
    let min = concurrency.scheduler_min_threads;
    let max = concurrency.scheduler_max_threads;
    ivm::set_scheduler_thread_limits(
        if min == 0 { None } else { Some(min) },
        if max == 0 { None } else { Some(max) },
    );
    let (effective_min, _effective_max) = ivm::parallel::default_scheduler_limits();
    println!("{}", scheduler_banner_line(effective_min));
    if concurrency.rayon_global_threads > 0
        && let Err(err) = ivm::init_global_rayon(concurrency.rayon_global_threads)
    {
        iroha_telemetry::metrics::record_stack_pool_fallback();
        iroha_logger::warn!(
            threads = %concurrency.rayon_global_threads,
            ?err,
            "Failed to set IVM Rayon global pool with the requested stack size; using existing pool"
        );
    }
}
/// Check the custody of the `<data_dir>/secrets/` key files the configuration parser may read
/// ([`node_secrets::verify_config_key_custody`]).
#[cfg(feature = "daemon")]
fn verify_config_key_custody(data_dir: &Path) -> Result<(), String> {
    node_secrets::verify_config_key_custody(&iroha_config::parameters::actual::DataDir::new(
        data_dir.to_path_buf(),
    ))
    .map_err(|error| error.to_string())
}
/// Non-daemon builds have no fixed-secret runtime provider.
#[cfg(not(feature = "daemon"))]
fn verify_config_key_custody(_data_dir: &Path) -> Result<(), String> {
    Ok(())
}
/// Sora Nexus features that a flat configuration may enable only together with `--sora`.
///
/// A profile node file is exempt: its compiled profile owns these settings.
fn sora_features_requiring_flag(config: &Config) -> Vec<&'static str> {
    let mut features = Vec::new();
    if config.torii.sorafs_storage.enabled
        || config.torii.sorafs_discovery.discovery_enabled
        || config.torii.sorafs_repair.enabled
        || config.torii.sorafs_gc.enabled
    {
        features.push("SoraFS");
    }
    if nexus_topology_is_custom(&config.nexus) {
        features.push("multi-lane routing");
    }
    if config.nexus.has_lane_overrides() {
        features.push("nexus lane configuration");
    }
    features
}
/// Read the configuration and then a genesis block if specified.
///
/// The returned configuration is **not** validated; call [`validate_config`] after
/// setting up logging to check for potential issues.
///
/// # Errors
/// - If failed to read the config
/// - If failed to load the genesis block
pub fn read_config_and_genesis(
    args: &Args,
) -> ReportResult<(Config, Option<GenesisBlock>), ConfigError> {
    read_config_and_genesis_with_filesystem_space(args, filesystem_space)
}

// The public startup owner always uses the real filesystem-space observation.
// Tests inject only capacity; path, identity, managed-byte and budget checks stay real.
fn read_config_and_genesis_with_filesystem_space(
    args: &Args,
    space: fn(&Path) -> Option<(u64, u64)>,
) -> ReportResult<(Config, Option<GenesisBlock>), ConfigError> {
    // Every configuration file goes through the node-file loader: a flat file is read as before
    // (with `extends` unless it is integrity-bound), a profile node file is layered over its
    // compiled profile, and a `data_dir` completes the fixed state and secret paths.
    let (config, profile_binding) = if let Some(path) = &args.config {
        let file = if let Some(expected) = args.startup.config_blake3.as_deref() {
            if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Report::new(ConfigError::ReadConfig)
                    .attach("`--config-blake3` must contain exactly 64 hexadecimal digits"));
            }
            let raw = read_bounded_startup_artifact(
                path,
                INTEGRITY_BOUND_CONFIG_MAX_BYTES_V1,
                "integrity-bound configuration",
            )
            .change_context(ConfigError::ReadConfig)
            .attach_with(|| {
                format!(
                    "failed to read integrity-bound configuration {}",
                    path.display()
                )
            })?;
            let observed = blake3::hash(&raw).to_hex().to_string();
            if !expected.eq_ignore_ascii_case(&observed) {
                return Err(Report::new(ConfigError::ReadConfig).attach(format!(
                    "integrity-bound configuration {} has BLAKE3 {observed}, expected {expected}",
                    path.display()
                )));
            }
            let raw_utf8 = std::str::from_utf8(&raw).map_err(|error| {
                Report::new(ConfigError::ReadConfig).attach(format!(
                    "integrity-bound configuration {} is not UTF-8: {error}",
                    path.display()
                ))
            })?;
            let table = raw_utf8.parse::<toml::Table>().map_err(|error| {
                Report::new(ConfigError::ReadConfig).attach(format!(
                    "failed to parse integrity-bound configuration {}: {error}",
                    path.display()
                ))
            })?;
            if table.contains_key("extends") {
                return Err(Report::new(ConfigError::ReadConfig).attach(format!(
                    "integrity-bound configuration {} must be flattened and cannot use `extends`",
                    path.display()
                )));
            }
            NodeFile::Verified {
                path: path.clone(),
                table,
            }
        } else {
            NodeFile::Path(path.clone())
        };
        let node = open_node_config(file, NodeConfigOptions { sora: args.sora })
            .change_context(ConfigError::ReadConfig)?;
        let data_dir = node.data_dir().map(Path::to_path_buf);
        let (reader, binding) = node.into_parts();
        // The parser reads the key files the configuration names under `<data_dir>/secrets/`;
        // they pass the runtime-secret custody checks first.
        if let Some(Err(error)) = data_dir.as_deref().map(verify_config_key_custody) {
            // Defuse the prepared reader's drop guard; the custody error replaces its report.
            let _ = reader.into_result();
            return Err(Report::new(ConfigError::ReadConfig).attach(error));
        }
        (reader, binding)
    } else {
        (ConfigReader::new(), None)
    };
    let sora_profile = iroha_config::sora_profile::SoraProfileSelection::from_reader(&config);
    let mut config = config
        .read_and_complete::<UserConfig>()
        .change_context(ConfigError::ReadConfig)?
        .parse()
        .change_context(ConfigError::ParseConfig)?;
    if let Some(path) = args.genesis_manifest_json.as_ref() {
        config.genesis.manifest_json = Some(WithOrigin::inline(path.clone()));
    }
    if args.sora {
        sora_profile.apply(&mut config);
    }
    let sora_features = sora_features_requiring_flag(&config);
    // A compiled profile owns its Nexus and SoraFS settings; `--sora` is rejected with it.
    if !args.sora && profile_binding.is_none() && !sora_features.is_empty() {
        let detail = sora_features.join(", ");
        return Err(
            Report::new(ConfigError::SoraProfileRequired).attach(format!(
                "Detected Sora Nexus features enabled without `--sora`: {detail}"
            )),
        );
    }
    config.apply_storage_budget();
    let storage_budget_filesystems = if config.kura.init_mode == InitMode::Fast {
        iroha_logger::warn!(
            "emergency Fast startup skipped recursive managed-storage measurement and runtime budget derivation until a Strict restart"
        );
        Vec::new()
    } else {
        reconcile_nexus_storage_budget(&mut config, space)?
    };
    warn_if_nexus_storage_budget_exceeds_available(&config, &storage_budget_filesystems);
    if let Some(mode) = args.fastpq_execution_mode {
        config.zk.fastpq.execution_mode = mode;
    }
    if let Some(mode) = args.fastpq_poseidon_mode {
        config.zk.fastpq.poseidon_mode = mode;
    }
    if let Some(device_class) = args.fastpq_device_class.as_deref() {
        let trimmed = device_class.trim();
        if trimmed.is_empty() {
            config.zk.fastpq.device_class = None;
        } else {
            config.zk.fastpq.device_class = Some(trimmed.to_owned());
        }
    }
    if let Some(chip_family) = args.fastpq_chip_family.as_deref() {
        let trimmed = chip_family.trim();
        if trimmed.is_empty() {
            config.zk.fastpq.chip_family = None;
        } else {
            config.zk.fastpq.chip_family = Some(trimmed.to_owned());
        }
    }
    if let Some(gpu_kind) = args.fastpq_gpu_kind.as_deref() {
        let trimmed = gpu_kind.trim();
        if trimmed.is_empty() {
            config.zk.fastpq.gpu_kind = None;
        } else {
            config.zk.fastpq.gpu_kind = Some(trimmed.to_owned());
        }
    }
    if let Err(err) =
        fastpq_prover::apply_metal_overrides(fastpq_metal_overrides_from_config(&config.zk.fastpq))
    {
        iroha_logger::warn!(
            target: "fastpq",
            %err,
            "failed to apply FASTPQ Metal overrides"
        );
    }
    #[cfg(feature = "fastpq-gpu")]
    if config.kura.init_mode != InitMode::Fast {
        preflight_fastpq_bn254_poseidon_words(&config.zk.fastpq);
    }
    // An offline configuration or storage check never starts a VM or worker pool. Keep
    // stdout reserved for its single result, and leave scheduler setup to the real
    // daemon startup path.
    if !args.startup.check_config && !args.startup.check_storage {
        if config.kura.init_mode == InitMode::Fast {
            // Fast constructs one inert State VM for structural completeness. Cap
            // that VM at one minimum-stack worker and leave the global Rayon pool
            // uninitialized; no contract or proof route is available in this mode.
            let _ = ivm::apply_stack_sizes(ivm::MIN_STACK_BYTES, ivm::MIN_STACK_BYTES);
            ivm::set_scheduler_thread_limits(Some(1), Some(1));
            println!("{}", scheduler_banner_line(1));
        } else {
            apply_concurrency_config(&config.concurrency);
        }
    }
    // Apply Norito settings immediately so subsequent Norito decode/encode (e.g., genesis)
    // uses the configured archive bounds and GPU offload policy.
    apply_norito_config(&config);
    if config.kura.init_mode == InitMode::Fast {
        norito::core::hw::set_gpu_compression_allowed(false);
    }
    // Apply hardware acceleration configuration for IVM (Metal/CUDA). Defaults enable all
    // available hardware; config can cap GPUs or disable specific backends. This does not
    // change outputs, only performance characteristics.
    if config.kura.init_mode == InitMode::Fast {
        let mut acceleration = config.accel.clone();
        acceleration.enable_simd = false;
        acceleration.enable_metal = false;
        acceleration.enable_cuda = false;
        acceleration.max_gpus = Some(0);
        apply_ivm_acceleration_config(&acceleration);
        rs16::set_simd_enabled(false);
    } else {
        apply_ivm_acceleration_config(&config.accel);
        rs16::set_simd_enabled(config.accel.enable_simd);
    }
    iroha_data_model::account::address::set_chain_discriminant(
        *config.common.chain_discriminant.value(),
    );
    let (genesis, _) = read_configured_genesis_with_bytes(config.genesis.file.as_ref())?;
    config.logger.terminal_colors = args.terminal_colors;
    Ok((config, genesis))
}
fn read_configured_genesis_with_bytes(
    signed_file: Option<&WithOrigin<PathBuf>>,
) -> ReportResult<(Option<GenesisBlock>, Option<Vec<u8>>), ConfigError> {
    let Some(signed_file) = signed_file else {
        return Ok((None, None));
    };
    let (genesis, bytes) = read_genesis_with_bytes(&signed_file.resolve_relative_path())
        .attach(signed_file.clone().into_attachment().display_path())?;
    Ok((Some(genesis), Some(bytes)))
}
#[cfg(test)]
mod configured_genesis_tests {
    use super::*;
    #[test]
    fn configured_genesis_is_always_read_and_authenticated() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let invalid = temp.path().join("invalid-genesis.nrt");
        fs::write(&invalid, b"not a signed genesis").unwrap();
        assert!(read_configured_genesis_with_bytes(Some(&WithOrigin::inline(invalid))).is_err());
        let missing = WithOrigin::inline(temp.path().join("missing-genesis.nrt"));
        assert!(read_configured_genesis_with_bytes(Some(&missing)).is_err());
        let (genesis, bytes) = read_configured_genesis_with_bytes(None).unwrap();
        assert!(genesis.is_none() && bytes.is_none());
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct StorageBudgetFilesystemProbe {
    filesystem_id: String,
    path: PathBuf,
    total_bytes: u64,
    available_bytes: u64,
    managed_bytes: u64,
    components: Vec<NexusStorageBudgetComponent>,
    managed_roots: Vec<PathBuf>,
    derived_budget_bytes: Option<u64>,
}
fn reconcile_nexus_storage_budget(
    config: &mut Config,
    space: fn(&Path) -> Option<(u64, u64)>,
) -> ReportResult<Vec<StorageBudgetFilesystemProbe>, ConfigError> {
    if config.nexus.storage.local_budget_bytes.is_some() {
        return probe_nexus_storage_filesystems(config, space);
    }
    let mut filesystems = probe_nexus_storage_filesystems(config, space)?;
    let filesystem_budgets = derive_runtime_nexus_storage_budget(&filesystems)?;
    let aggregate_budget_bytes = config
        .apply_derived_storage_budget(&filesystem_budgets)
        .map_err(|error| {
            Report::new(ConfigError::ParseConfig).attach(format!(
                "failed to apply runtime Nexus storage budget: {error}"
            ))
        })?;
    for (filesystem, budget) in filesystems.iter_mut().zip(&filesystem_budgets) {
        filesystem.derived_budget_bytes = Some(budget.budget_bytes.get());
        iroha_logger::info!(
            filesystem_id = %filesystem.filesystem_id,
            path = %filesystem.path.display(),
            components = ?nexus_storage_component_labels(&filesystem.components),
            total_bytes = filesystem.total_bytes,
            available_bytes = filesystem.available_bytes,
            managed_bytes = filesystem.managed_bytes,
            budget_bytes = budget.budget_bytes.get(),
            "derived runtime-only Nexus storage budget"
        );
    }
    iroha_logger::info!(
        aggregate_budget_bytes = aggregate_budget_bytes.get(),
        filesystem_groups = filesystem_budgets.len(),
        "activated runtime-only Nexus storage budget; operator configuration remains unchanged"
    );
    Ok(filesystems)
}
fn probe_nexus_storage_filesystems(
    config: &Config,
    space: fn(&Path) -> Option<(u64, u64)>,
) -> ReportResult<Vec<StorageBudgetFilesystemProbe>, ConfigError> {
    let mut groups = BTreeMap::<String, StorageBudgetFilesystemProbe>::new();
    for (component, root) in effective_nexus_storage_component_roots(config) {
        let lexical_root = normalize_budget_probe_path(root).ok_or_else(|| {
            Report::new(ConfigError::ParseConfig).attach(format!(
                "failed to resolve Nexus storage root for component `{}` against the current directory",
                component.as_str()
            ))
        })?;
        let resolved_root = resolve_budget_probe_root(&lexical_root, component)?;
        let probe_path = resolved_root.probe_path;
        let filesystem_id = filesystem_identity(&probe_path).ok_or_else(|| {
            filesystem_probe_config_error(format!(
                "failed to determine the filesystem identity for `{}` (component `{}`)",
                probe_path.display(),
                component.as_str()
            ))
        })?;
        let (available_bytes, total_bytes) = space(&probe_path).ok_or_else(|| {
            filesystem_probe_config_error(format!(
                "failed to determine filesystem capacity for `{}` (component `{}`)",
                probe_path.display(),
                component.as_str()
            ))
        })?;
        let managed_root = resolved_root.managed_root;
        groups
            .entry(filesystem_id.clone())
            .and_modify(|group| {
                group.available_bytes = group.available_bytes.min(available_bytes);
                group.total_bytes = group.total_bytes.min(total_bytes);
                if !group.components.contains(&component) {
                    group.components.push(component);
                }
                if let Some(managed_root) = managed_root.as_ref()
                    && !group.managed_roots.contains(managed_root)
                {
                    group.managed_roots.push(managed_root.clone());
                }
            })
            .or_insert_with(|| StorageBudgetFilesystemProbe {
                filesystem_id,
                path: probe_path,
                total_bytes,
                available_bytes,
                managed_bytes: 0,
                components: vec![component],
                managed_roots: managed_root.into_iter().collect(),
                derived_budget_bytes: None,
            });
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    for group in &mut groups {
        group.components.sort_unstable();
        deduplicate_managed_roots(&mut group.managed_roots);
        group.managed_bytes = group.managed_roots.iter().try_fold(0_u64, |total, root| {
            let bytes = managed_root_size(root, &group.filesystem_id).map_err(|error| {
                Report::new(ConfigError::ParseConfig).attach(format!(
                    "failed to measure Nexus managed storage root `{}`: {error}",
                    root.display()
                ))
            })?;
            total.checked_add(bytes).ok_or_else(|| {
                Report::new(ConfigError::ParseConfig).attach(format!(
                    "managed Nexus storage byte count overflowed for filesystem `{}`",
                    group.filesystem_id
                ))
            })
        })?;
    }
    groups.sort_by_key(|group| {
        group.components.first().map_or(usize::MAX, |component| {
            nexus_storage_component_order(*component)
        })
    });
    Ok(groups)
}
fn effective_nexus_storage_component_roots(
    config: &Config,
) -> Vec<(NexusStorageBudgetComponent, PathBuf)> {
    let mut roots = vec![(
        NexusStorageBudgetComponent::Kura,
        config.kura.store_dir.resolve_relative_path(),
    )];
    let tiered_state_root = config
        .tiered_state
        .da_store_root
        .clone()
        .or_else(|| config.tiered_state.cold_store_root.clone())
        .or_else(|| {
            (config.nexus.storage.max_wsv_memory_bytes.get() > 0).then(|| {
                PathBuf::from(
                    iroha_config::parameters::defaults::tiered_state::DEFAULT_COLD_STORE_ROOT,
                )
            })
        });
    if let Some(tiered_state_root) = tiered_state_root {
        roots.push((NexusStorageBudgetComponent::WsvCold, tiered_state_root));
    }
    roots.push((
        NexusStorageBudgetComponent::Sorafs,
        config.torii.sorafs_storage.data_dir.clone(),
    ));
    roots
}
fn derive_runtime_nexus_storage_budget(
    filesystems: &[StorageBudgetFilesystemProbe],
) -> ReportResult<Vec<NexusStorageFilesystemBudget>, ConfigError> {
    let mut filesystem_budgets = Vec::with_capacity(filesystems.len());
    for filesystem in filesystems {
        let total_bytes = u128::from(filesystem.total_bytes);
        let headroom_bps = u128::from(
            iroha_config::parameters::defaults::nexus::storage::AUTO_STORAGE_HEADROOM_BPS,
        );
        let bps_total = u128::from(iroha_config::parameters::defaults::nexus::storage::BPS_TOTAL);
        let reserve_bytes = total_bytes
            .checked_mul(headroom_bps)
            .and_then(|value| value.checked_add(bps_total.saturating_sub(1)))
            .map(|value| value / bps_total)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| {
                Report::new(ConfigError::ParseConfig).attach(format!(
                    "failed to derive Nexus storage headroom for filesystem `{}`",
                    filesystem.filesystem_id
                ))
            })?;
        let usable_bytes = filesystem
            .managed_bytes
            .checked_add(filesystem.available_bytes)
            .ok_or_else(|| {
                Report::new(ConfigError::ParseConfig).attach(format!(
                    "managed plus available bytes overflowed for Nexus storage filesystem `{}`",
                    filesystem.filesystem_id
                ))
            })?;
        let budget_bytes = usable_bytes
            .checked_sub(reserve_bytes)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| {
                Report::new(ConfigError::ParseConfig).attach(format!(
                    "filesystem `{}` has no safe non-zero Nexus storage budget after reserving {reserve_bytes} bytes of headroom; configure nexus.storage.local_budget_bytes explicitly only after freeing space",
                    filesystem.filesystem_id
                ))
            })?;
        if budget_bytes.get() < filesystem.managed_bytes {
            return Err(Report::new(ConfigError::ParseConfig).attach(format!(
                "filesystem `{}` derived budget {} is below the {} managed bytes after reserving {reserve_bytes} bytes of headroom; free space before startup or configure nexus.storage.local_budget_bytes deliberately",
                filesystem.filesystem_id,
                budget_bytes.get(),
                filesystem.managed_bytes
            )));
        }
        filesystem_budgets.push(NexusStorageFilesystemBudget {
            budget_bytes,
            components: filesystem.components.clone(),
        });
    }
    if filesystem_budgets.is_empty() {
        return Err(Report::new(ConfigError::ParseConfig)
            .attach("runtime Nexus storage derivation produced no filesystem budget groups"));
    }
    Ok(filesystem_budgets)
}
fn warn_if_nexus_storage_budget_exceeds_available(
    config: &Config,
    filesystems: &[StorageBudgetFilesystemProbe],
) {
    if filesystems.is_empty() {
        return;
    }
    if filesystems
        .iter()
        .all(|filesystem| filesystem.derived_budget_bytes.is_some())
    {
        return;
    }
    for filesystem in filesystems {
        let Some(assigned_budget) = operator_explicit_budget_shortfall(config, filesystem) else {
            continue;
        };
        iroha_logger::warn!(
            filesystem_id = %filesystem.filesystem_id,
            path = %filesystem.path.display(),
            components = ?nexus_storage_component_labels(&filesystem.components),
            assigned_budget_bytes = assigned_budget,
            managed_bytes = filesystem.managed_bytes,
            available_bytes = filesystem.available_bytes,
            "effective operator-configured Nexus storage caps exceed safe available disk space on a filesystem"
        );
    }
}
fn operator_explicit_budget_shortfall(
    config: &Config,
    filesystem: &StorageBudgetFilesystemProbe,
) -> Option<u64> {
    let assigned_budget = effective_assigned_budget_for_filesystem(config, filesystem);
    let required_growth = assigned_budget.saturating_sub(filesystem.managed_bytes);
    (required_growth > filesystem.available_bytes).then_some(assigned_budget)
}
fn effective_assigned_budget_for_filesystem(
    config: &Config,
    filesystem: &StorageBudgetFilesystemProbe,
) -> u64 {
    filesystem
        .components
        .iter()
        .fold(0_u64, |total, component| {
            let component_budget = match component {
                NexusStorageBudgetComponent::Kura => config.kura.max_disk_usage_bytes.get(),
                NexusStorageBudgetComponent::WsvCold => config.tiered_state.max_cold_bytes.get(),
                NexusStorageBudgetComponent::Sorafs => {
                    config.torii.sorafs_storage.max_capacity_bytes.get()
                }
            };
            total.saturating_add(component_budget)
        })
}
fn nexus_storage_component_labels(components: &[NexusStorageBudgetComponent]) -> Vec<&'static str> {
    components
        .iter()
        .map(|component| component.as_str())
        .collect()
}
fn nexus_storage_component_order(component: NexusStorageBudgetComponent) -> usize {
    NexusStorageBudgetComponent::ORDER
        .iter()
        .position(|ordered| ordered == &component)
        .unwrap_or(usize::MAX)
}
fn normalize_budget_probe_path(path: PathBuf) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => {
                normalized.push(std::path::MAIN_SEPARATOR_STR);
            }
            std::path::Component::Normal(segment) => normalized.push(segment),
        }
    }
    Some(normalized)
}
fn nearest_existing_ancestor(path: &Path) -> std::io::Result<Option<PathBuf>> {
    let mut current = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&current) {
            Ok(_) => return Ok(Some(current)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}
#[derive(Debug)]
struct ResolvedStorageBudgetRoot {
    probe_path: PathBuf,
    managed_root: Option<PathBuf>,
}
fn resolve_budget_probe_root(
    lexical_root: &Path,
    component: NexusStorageBudgetComponent,
) -> ReportResult<ResolvedStorageBudgetRoot, ConfigError> {
    let existing_ancestor = nearest_existing_ancestor(lexical_root)
        .map_err(|error| {
            filesystem_probe_config_error(format!(
                "failed to inspect Nexus storage root `{}` (component `{}`): {error}",
                lexical_root.display(),
                component.as_str()
            ))
        })?
        .ok_or_else(|| {
            filesystem_probe_config_error(format!(
                "failed to find an existing ancestor for Nexus storage root `{}` (component `{}`)",
                lexical_root.display(),
                component.as_str()
            ))
        })?;
    let existing_metadata = fs::symlink_metadata(&existing_ancestor).map_err(|error| {
        filesystem_probe_config_error(format!(
            "failed to recheck Nexus storage ancestor `{}` (component `{}`): {error}",
            existing_ancestor.display(),
            component.as_str()
        ))
    })?;
    let root_exists = existing_ancestor == lexical_root;
    if root_exists && metadata_is_symlink_or_reparse(&existing_metadata) {
        return Err(filesystem_probe_config_error(format!(
            "Nexus storage root `{}` (component `{}`) must not be a symbolic link or reparse point",
            lexical_root.display(),
            component.as_str()
        )));
    }
    let canonical_ancestor = fs::canonicalize(&existing_ancestor).map_err(|error| {
        filesystem_probe_config_error(format!(
            "failed to canonicalize Nexus storage ancestor `{}` (component `{}`): {error}",
            existing_ancestor.display(),
            component.as_str()
        ))
    })?;
    let canonical_metadata = fs::metadata(&canonical_ancestor).map_err(|error| {
        filesystem_probe_config_error(format!(
            "failed to inspect canonical Nexus storage ancestor `{}` (component `{}`): {error}",
            canonical_ancestor.display(),
            component.as_str()
        ))
    })?;
    if !canonical_metadata.is_dir() {
        return Err(filesystem_probe_config_error(format!(
            "Nexus storage ancestor `{}` (component `{}`) is not a directory",
            canonical_ancestor.display(),
            component.as_str()
        )));
    }
    let missing_suffix = lexical_root
        .strip_prefix(&existing_ancestor)
        .expect("nearest ancestor must prefix the normalized storage root");
    let canonical_root = normalize_budget_probe_path(canonical_ancestor.join(missing_suffix))
        .ok_or_else(|| {
            filesystem_probe_config_error(format!(
                "failed to normalize canonical Nexus storage root `{}` (component `{}`)",
                lexical_root.display(),
                component.as_str()
            ))
        })?;
    let probe_path = if root_exists {
        canonical_root.clone()
    } else {
        canonical_ancestor
    };
    Ok(ResolvedStorageBudgetRoot {
        probe_path,
        managed_root: root_exists.then_some(canonical_root),
    })
}
fn metadata_is_symlink_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(target_os = "windows"))]
    false
}
fn deduplicate_managed_roots(roots: &mut Vec<PathBuf>) {
    roots.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    let mut unique = Vec::<PathBuf>::with_capacity(roots.len());
    for root in std::mem::take(roots) {
        if !unique.iter().any(|ancestor| root.starts_with(ancestor)) {
            unique.push(root);
        }
    }
    *roots = unique;
}
fn managed_root_size(path: &Path, expected_filesystem_id: &str) -> std::io::Result<u64> {
    managed_root_size_with_identity(path, expected_filesystem_id, filesystem_identity)
}
fn managed_root_size_with_identity<F>(
    path: &Path,
    expected_filesystem_id: &str,
    identity: F,
) -> std::io::Result<u64>
where
    F: Fn(&Path) -> Option<String>,
{
    let metadata = fs::symlink_metadata(path)?;
    if metadata_is_symlink_or_reparse(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "managed storage root must not be a symbolic link or reparse point",
        ));
    }
    if identity(path).as_deref() != Some(expected_filesystem_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "managed storage root moved to a different filesystem during probing",
        ));
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    let mut total = 0_u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let entry_path = entry.path();
            let entry_metadata = fs::symlink_metadata(&entry_path)?;
            if metadata_is_symlink_or_reparse(&entry_metadata) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "managed storage tree contains symbolic link or reparse point `{}`",
                        entry_path.display()
                    ),
                ));
            }
            let entry_filesystem_id = identity(&entry_path).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "failed to determine filesystem identity for managed storage entry `{}`",
                        entry_path.display()
                    ),
                )
            })?;
            if entry_filesystem_id != expected_filesystem_id {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "managed storage entry `{}` crosses from filesystem `{expected_filesystem_id}` to `{entry_filesystem_id}`",
                        entry_path.display()
                    ),
                ));
            }
            if entry_metadata.is_dir() {
                stack.push(entry_path);
            } else if entry_metadata.is_file() {
                total = total.checked_add(entry_metadata.len()).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "managed storage byte count overflowed u64",
                    )
                })?;
            }
        }
    }
    let final_metadata = fs::symlink_metadata(path)?;
    if metadata_is_symlink_or_reparse(&final_metadata)
        || identity(path).as_deref() != Some(expected_filesystem_id)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "managed storage root changed identity during measurement",
        ));
    }
    Ok(total)
}
fn filesystem_probe_config_error(detail: String) -> Report<ConfigError> {
    let report = Report::new(ConfigError::ParseConfig).attach(detail);
    #[cfg(not(any(unix, target_os = "windows")))]
    let report = report.attach("Nexus storage filesystem probing is unsupported on this platform");
    report
}
#[cfg(unix)]
fn filesystem_identity(path: &Path) -> Option<String> {
    let stats = rustix::fs::stat(path).ok()?;
    Some(format!("dev:{}", stats.st_dev))
}
#[cfg(target_os = "windows")]
fn filesystem_identity(path: &Path) -> Option<String> {
    let volume_mount_point = windows_volume_mount_point(path)?;
    let volume_name = windows_volume_name_for_mount_point(&volume_mount_point)?;
    Some(normalize_windows_volume_identity(&volume_name))
}
#[cfg(unix)]
fn filesystem_space(path: &Path) -> Option<(u64, u64)> {
    let stats = rustix::fs::statvfs(path).ok()?;
    let fragment_size = statvfs_fragment_size(stats.f_frsize, stats.f_bsize)?;
    let available_bytes = stats.f_bavail.checked_mul(fragment_size)?;
    let total_bytes = stats.f_blocks.checked_mul(fragment_size)?;
    Some((available_bytes, total_bytes))
}
#[cfg(unix)]
fn statvfs_fragment_size(fragment_size: u64, block_size: u64) -> Option<u64> {
    (0 < fragment_size)
        .then_some(fragment_size)
        .or_else(|| (0 < block_size).then_some(block_size))
}
#[cfg(target_os = "windows")]
fn filesystem_space(path: &Path) -> Option<(u64, u64)> {
    let wide_path = windows_wide_path(path);
    let mut free_bytes_available = 0_u64;
    let mut total_bytes = 0_u64;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide_path.as_ptr(),
            &mut free_bytes_available,
            &mut total_bytes,
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some((free_bytes_available, total_bytes))
}
#[cfg(not(any(unix, target_os = "windows")))]
fn filesystem_space(_path: &Path) -> Option<(u64, u64)> {
    None
}
#[cfg(not(any(unix, target_os = "windows")))]
fn filesystem_identity(_path: &Path) -> Option<String> {
    None
}
#[cfg(any(target_os = "windows", test))]
fn normalize_windows_volume_mount_point(volume_mount_point: &str) -> String {
    let mut normalized = volume_mount_point.replace('/', "\\");
    if !normalized.ends_with('\\') {
        normalized.push('\\');
    }
    normalized
}
#[cfg(any(target_os = "windows", test))]
fn normalize_windows_volume_identity(volume_name: &str) -> String {
    let mut normalized = normalize_windows_volume_mount_point(volume_name);
    normalized.make_ascii_lowercase();
    format!("volume:{normalized}")
}
#[cfg(any(target_os = "windows", test))]
fn windows_string_from_wide_buffer(buffer: &[u16]) -> Option<String> {
    let end = buffer.iter().position(|&unit| unit == 0)?;
    Some(String::from_utf16_lossy(&buffer[..end]))
}
#[cfg(target_os = "windows")]
const WINDOWS_FILESYSTEM_PROBE_BUFFER_LEN: usize = 32_768;
#[cfg(target_os = "windows")]
#[allow(non_snake_case)]
unsafe extern "system" {
    fn GetDiskFreeSpaceExW(
        lp_directory_name: *const u16,
        lp_free_bytes_available_to_caller: *mut u64,
        lp_total_number_of_bytes: *mut u64,
        lp_total_number_of_free_bytes: *mut u64,
    ) -> i32;
    fn GetVolumeNameForVolumeMountPointW(
        lpsz_volume_mount_point: *const u16,
        lpsz_volume_name: *mut u16,
        cch_buffer_length: u32,
    ) -> i32;
    fn GetVolumePathNameW(
        lpsz_file_name: *const u16,
        lpsz_volume_path_name: *mut u16,
        cch_buffer_length: u32,
    ) -> i32;
}
#[cfg(target_os = "windows")]
fn windows_wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
#[cfg(target_os = "windows")]
fn windows_wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
#[cfg(target_os = "windows")]
fn windows_query_volume_string<F>(mut query: F) -> Option<String>
where
    F: FnMut(*mut u16, u32) -> i32,
{
    let mut buffer = vec![0_u16; WINDOWS_FILESYSTEM_PROBE_BUFFER_LEN];
    (query(buffer.as_mut_ptr(), buffer.len() as u32) != 0)
        .then(|| windows_string_from_wide_buffer(&buffer))
        .flatten()
}
#[cfg(target_os = "windows")]
fn windows_volume_mount_point(path: &Path) -> Option<String> {
    let wide_path = windows_wide_path(path);
    windows_query_volume_string(|buffer, len| unsafe {
        GetVolumePathNameW(wide_path.as_ptr(), buffer, len)
    })
    .map(|mount_point| normalize_windows_volume_mount_point(&mount_point))
}
#[cfg(target_os = "windows")]
fn windows_volume_name_for_mount_point(volume_mount_point: &str) -> Option<String> {
    let wide_mount_point = windows_wide_string(volume_mount_point);
    windows_query_volume_string(|buffer, len| unsafe {
        GetVolumeNameForVolumeMountPointW(wide_mount_point.as_ptr(), buffer, len)
    })
}
pub(crate) fn apply_ivm_acceleration_config(
    accel: &iroha_config::parameters::actual::Acceleration,
) {
    let ivm_cfg = ivm::AccelerationConfig {
        resource_limits: accel.resource_limits,
        enable_simd: accel.enable_simd,
        enable_metal: accel.enable_metal,
        enable_cuda: accel.enable_cuda,
        max_gpus: accel.max_gpus,
        merkle_min_leaves_gpu: Some(accel.merkle_min_leaves_gpu),
        merkle_min_leaves_metal: accel.merkle_min_leaves_metal,
        merkle_min_leaves_cuda: accel.merkle_min_leaves_cuda,
        prefer_cpu_sha2_max_leaves_aarch64: accel.prefer_cpu_sha2_max_leaves_aarch64,
        prefer_cpu_sha2_max_leaves_x86: accel.prefer_cpu_sha2_max_leaves_x86,
    };
    ivm::set_acceleration_config(ivm_cfg);
}
#[cfg(test)]
mod config_tests {
    use super::*;
    use iroha_config_base::toml::TomlSource;
    #[test]
    fn soracloud_runtime_manager_corridor_has_no_local_key_fallback() {
        let source = include_str!("main.rs");
        let start = source
            .find("let local_validator_account_id =")
            .expect("Soracloud identity corridor");
        let end = source[start..]
            .find("let runtime_manager = if let Some(signer)")
            .map(|offset| start + offset)
            .expect("Soracloud sink injection corridor");
        let corridor = &source[start..end];
        assert!(
            !corridor.contains("config.common.key_pair"),
            "Soracloud mutation authority must never fall back to the process-local node key"
        );
    }
    #[test]
    fn soracloud_production_fails_before_startup_without_signer_binding() {
        let mut dependencies = IrohaRuntimeDeps::default();
        assert_eq!(
            qualify_soracloud_runtime_signer_for_startup(true, None, &mut dependencies),
            Err("production mode requires an exact configured signer binding")
        );
        assert!(
            qualify_soracloud_runtime_signer_for_startup(false, None, &mut dependencies).is_ok(),
            "unbound non-production mode must remain read-only"
        );
        assert!(dependencies.is_empty());
    }
    #[test]
    fn native_signer_presence_gate_accepts_only_exact_enabled_and_disabled_shapes() {
        assert!(
            validate_sorafs_native_signer_role_presence("proof_outcome", true, true, true).is_ok()
        );
        assert!(
            validate_sorafs_native_signer_role_presence("proof_outcome", false, false, false)
                .is_ok()
        );
    }
    #[test]
    fn storage_enabled_requires_native_signers_independently_of_generation_flags() {
        assert!(sorafs_native_signer_role_required(true, false));
        assert!(sorafs_native_signer_role_required(true, true));
        assert!(sorafs_native_signer_role_required(false, true));
        assert!(!sorafs_native_signer_role_required(false, false));
    }
    #[test]
    fn native_signer_presence_gate_rejects_enabled_missing_and_disabled_injected_roles() {
        assert_eq!(
            validate_sorafs_native_signer_role_presence("proof_outcome", true, false, false),
            Err(
                "required SoraFS proof_outcome signer role is missing its configured binding for storage-enabled durable drain or role generation"
                    .to_owned(),
            )
        );
        assert_eq!(
            validate_sorafs_native_signer_role_presence(
                "proof_outcome",
                false,
                false,
                true
            ),
            Err(
                "unconfigured SoraFS proof_outcome signer role rejects an injected runtime provider"
                    .to_owned()
            )
        );
    }
    #[test]
    fn native_signer_presence_gate_rejects_configured_missing_and_disabled_binding_roles() {
        assert_eq!(
            validate_sorafs_native_signer_role_presence("proof_outcome", true, true, false),
            Err(
                "configured SoraFS proof_outcome signer role is missing its runtime provider"
                    .to_owned()
            )
        );
        assert_eq!(
            validate_sorafs_native_signer_role_presence("proof_outcome", false, true, true),
            Err(
                "inactive SoraFS proof_outcome signer role rejects a configured binding without storage-enabled durable drain or role generation"
                    .to_owned(),
            )
        );
    }
    use iroha_crypto::Hash;
    use iroha_model_base::topology::DataSpaceId;
    use std::{io::Write, path::Path};
    use tempfile::NamedTempFile;
    use toml::Table;
    pub fn minimal_config_table() -> Table {
        toml::from_str(
            r#"chain = "00000000-0000-0000-0000-000000000000"
public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
private_key = "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
soranet_transport_public_key = "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B"
soranet_transport_private_key = "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89"
nexus.storage.local_budget_bytes = 4096
trusted_peers_pop = [
  { public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2", pop_hex = "8515da750f81182aaba5c22fc9f03a01e81ed85e4495a2ca6b29a71c0c8549537e31e79cddf6ff285b9e22d0d9dc17ce0f46e7d0cf78b2ef9feab50c849a1ea8e1e4f07e966f6113faa8a999317545d9f111b8e08a7273913710b43a20b19c08" }
]
[network]
address = "addr:127.0.0.1:1337#8F78"
public_address = "addr:127.0.0.1:1337#8F78"
[torii]
address = "addr:127.0.0.1:8080#8942"
[genesis]
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
expected_hash = "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
[streaming]
identity_public_key = "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB"
identity_private_key = "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F"
"#,
        )
        .expect("minimal config")
    }
    #[test]
    fn emergency_fast_startup_ignores_runtime_checks_for_services_it_disables() {
        let mut config = Config::from_toml_source(TomlSource::inline(minimal_config_table()))
            .expect("minimal config parses");
        config.torii.sorafs_storage.enabled = true;
        config.torii.sorafs_gateway.compliance = None;

        assert!(
            validate_config(&config).is_err(),
            "Strict startup must reject an incomplete enabled runtime"
        );
        config.kura.init_mode = InitMode::Fast;
        validate_startup_config(&config).expect("Fast disables SoraFS before runtime construction");
        validate_startup_config_offline(&config)
            .expect("Fast must not resolve disabled runtime providers");
    }
    #[cfg(feature = "telemetry")]
    #[test]
    fn runtime_validation_rejects_configured_but_disabled_telemetry() {
        let mut table = minimal_config_table();
        iroha_config::base::toml::Writer::new(&mut table)
            .write("telemetry_profile", "disabled")
            .write(["telemetry", "url"], "ws://collector.example/events");
        let config = Config::from_toml_source(TomlSource::inline(table))
            .expect("disabled telemetry config parses structurally");
        let mut emitter = Emitter::new();
        validate_config_runtime(&mut emitter, &config);
        let error = emitter
            .into_result()
            .expect_err("inactive telemetry sink must fail runtime validation");
        assert!(
            format!("{error:?}").contains("disables telemetry"),
            "{error:?}"
        );
    }
    #[test]
    fn runtime_validation_rejects_integrity_state_without_a_sink() {
        let mut config = Config::from_toml_source(TomlSource::inline(minimal_config_table()))
            .expect("minimal config parses");
        config.telemetry_integrity.state_dir = Some(PathBuf::from("telemetry-state"));
        let mut emitter = Emitter::new();
        validate_config_runtime(&mut emitter, &config);
        let error = emitter
            .into_result()
            .expect_err("dormant integrity state must fail runtime validation");
        assert!(
            format!("{error:?}").contains("require a configured telemetry sink"),
            "{error:?}"
        );
    }
    pub fn multilane_config_table() -> Table {
        toml::from_str(
            r#"chain = "00000000-0000-0000-0000-000000000000"
public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
private_key = "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
soranet_transport_public_key = "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B"
soranet_transport_private_key = "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89"
trusted_peers_pop = [
  { public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2", pop_hex = "8515da750f81182aaba5c22fc9f03a01e81ed85e4495a2ca6b29a71c0c8549537e31e79cddf6ff285b9e22d0d9dc17ce0f46e7d0cf78b2ef9feab50c849a1ea8e1e4f07e966f6113faa8a999317545d9f111b8e08a7273913710b43a20b19c08" }
]
[network]
address = "addr:127.0.0.1:1337#8F78"
public_address = "addr:127.0.0.1:1337#8F78"
[torii]
address = "addr:127.0.0.1:8080#8942"
[genesis]
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
expected_hash = "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
[streaming]
identity_public_key = "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB"
identity_private_key = "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F"
[nexus]
lane_count = 2
[[nexus.lane_catalog]]
index = 0
alias = "core"
metadata = {}
[[nexus.lane_catalog]]
index = 1
alias = "zk"
metadata = {}
"#
        )
        .expect("multilane config")
    }
    const NEXUS_DEFAULTS_BLAKE2B: &str =
        "37af6d032c455549e0e10568d910720bc0ec6b5b67f03ffe47fc62469a90f65d";
    fn file_blake2b_hex(path: &Path) -> String {
        let bytes = std::fs::read(path).expect("read file");
        Hash::new(bytes).to_string()
    }
    pub fn load_unprovisioned_profile_for_inspection(path: &Path) -> Config {
        let source = std::fs::read_to_string(path).expect("read checked-in signing profile");
        let mut table: Table = toml::from_str(&source).expect("parse signing profile TOML");
        if table.remove("private_key_file").is_some() {
            let fixture = minimal_config_table();
            for key in [
                "private_key",
                "soranet_transport_public_key",
                "soranet_transport_private_key",
            ] {
                table.insert(key.to_owned(), fixture[key].clone());
            }
            let transport_file = table.remove("soranet_transport_private_key_file");
            assert!(transport_file.is_some());
            let streaming = table
                .get_mut("streaming")
                .and_then(toml::Value::as_table_mut)
                .expect("signing profile streaming table");
            assert!(streaming.remove("identity_private_key_file").is_some());
            for key in ["identity_public_key", "identity_private_key"] {
                streaming.insert(key.to_owned(), fixture["streaming"][key].clone());
            }
        }
        let genesis = table
            .get_mut("genesis")
            .and_then(toml::Value::as_table_mut)
            .expect("signing profile genesis table");
        if genesis.remove("expected_hash_file").is_some() {
            assert!(!genesis.contains_key("expected_hash"));
            // Profile inspection cannot read a genesis identity emitted only by
            // provisioning. This fixture identity never authorizes node startup.
            genesis.insert(
                "expected_hash".to_owned(),
                minimal_config_table()["genesis"]["expected_hash"].clone(),
            );
        }

        Config::from_toml_source(TomlSource::inline(table))
            .expect("resolve signing profile for non-runtime inspection")
    }
    #[test]
    fn operator_signatures_allowlist_adds_node_key_when_enabled() {
        let mut config = Config::from_toml_source(TomlSource::inline(minimal_config_table()))
            .expect("default config");
        let node_public_key = config.common.key_pair.public_key().clone();
        config.torii.operator_signatures.allow_node_key = true;
        config.torii.operator_signatures.allowed_public_keys.clear();
        ensure_operator_node_key_allowlisted(&mut config);
        assert!(
            config
                .torii
                .operator_signatures
                .allowed_public_keys
                .contains(&node_public_key),
            "node public key should be allow-listed when allow_node_key is enabled"
        );
    }
    #[test]
    fn operator_signatures_allowlist_keeps_node_key_unique() {
        let mut config = Config::from_toml_source(TomlSource::inline(minimal_config_table()))
            .expect("default config");
        let node_public_key = config.common.key_pair.public_key().clone();
        config.torii.operator_signatures.allow_node_key = true;
        config
            .torii
            .operator_signatures
            .allowed_public_keys
            .push(node_public_key.clone());
        ensure_operator_node_key_allowlisted(&mut config);
        let count = config
            .torii
            .operator_signatures
            .allowed_public_keys
            .iter()
            .filter(|key| *key == &node_public_key)
            .count();
        assert_eq!(count, 1, "node public key should not be duplicated");
    }
    #[test]
    fn operator_signatures_allowlist_respects_disabled_node_key_flag() {
        let mut config = Config::from_toml_source(TomlSource::inline(minimal_config_table()))
            .expect("default config");
        config.torii.operator_signatures.allow_node_key = false;
        config.torii.operator_signatures.allowed_public_keys.clear();
        ensure_operator_node_key_allowlisted(&mut config);
        assert!(
            config
                .torii
                .operator_signatures
                .allowed_public_keys
                .is_empty(),
            "allow-list should remain unchanged when allow_node_key is disabled"
        );
    }
    #[test]
    fn sora_profile_installs_nexus_catalog() {
        let mut config = Config::from_toml_source(TomlSource::inline(minimal_config_table()))
            .expect("default config");
        config.apply_sora_profile();
        assert_eq!(config.nexus.lane_catalog.lane_count().get(), 3);
        assert_eq!(config.nexus.lane_config.entries().len(), 3);
        let lane_aliases: Vec<_> = config
            .nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.alias.as_str())
            .collect();
        assert_eq!(lane_aliases, ["core", "governance", "zk"]);
        assert!(
            config
                .nexus
                .lane_catalog
                .lanes()
                .iter()
                .all(|lane| lane.dataspace_id == DataSpaceId::UNIVERSAL),
            "the Sora profile's logical lanes must share the universal physical dataspace"
        );
        let dataspace_aliases: Vec<_> = config
            .nexus
            .dataspace_catalog
            .entries()
            .iter()
            .map(|entry| entry.alias.as_str())
            .collect();
        assert_eq!(dataspace_aliases, ["universal"]);
        assert!(nexus_topology_is_custom(&config.nexus));
        assert!(
            !config.torii.sorafs_storage.enabled,
            "the portable Sora profile must not manufacture an embedded storage-provider role"
        );
    }
    #[test]
    fn multilane_configuration_installs_custom_nexus_topology() {
        let config = Config::from_toml_source(TomlSource::inline(multilane_config_table()))
            .expect("multilane config");
        assert!(nexus_topology_is_custom(&config.nexus));
    }
    #[test]
    fn nexus_profile_defaults_install_catalog() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../defaults/nexus/config.toml");
        assert!(
            Config::from_toml_source(
                TomlSource::from_file(path.clone()).expect("read nexus defaults config")
            )
            .is_err(),
            "the unprovisioned profile must not be a runnable node config"
        );
        let config = load_unprovisioned_profile_for_inspection(&path);
        assert!(
            !config.torii.sorafs_storage.enabled,
            "the portable Nexus template must leave provider storage explicit"
        );
        let signers = &config.torii.sorafs_storage.native_transaction_signers;
        assert!(signers.proof_outcome.is_none());
        assert!(signers.repair.is_none());
        assert!(signers.reserve.is_none());
        assert!(signers.orderbook.is_none());
        assert_eq!(config.nexus.dataspace_catalog.entries().len(), 1);
        assert!(nexus_topology_is_custom(&config.nexus));
        let lane_aliases: Vec<_> = config
            .nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.alias.as_str())
            .collect();
        assert_eq!(lane_aliases, ["core", "governance", "zk"]);
        let dataspace_aliases: Vec<_> = config
            .nexus
            .dataspace_catalog
            .entries()
            .iter()
            .map(|entry| entry.alias.as_str())
            .collect();
        assert_eq!(dataspace_aliases, ["universal"]);
    }
    #[test]
    fn nexus_profile_hash_matches_template() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../defaults/nexus/config.toml");
        let hash = file_blake2b_hex(&path);
        assert_eq!(hash, NEXUS_DEFAULTS_BLAKE2B);
    }
    #[test]
    fn sora_flag_installs_nexus_profile() {
        let mut config_file = NamedTempFile::new().expect("create temp config");
        let toml_value = toml::Value::Table(minimal_config_table());
        config_file
            .write_all(
                toml::to_string(&toml_value)
                    .expect("render config")
                    .as_bytes(),
            )
            .expect("write config");
        let args = parse_args_from(
            test_build_metadata(),
            [
                "iroha3d",
                "--sora",
                "--config",
                config_file
                    .path()
                    .to_str()
                    .expect("temp config path to string"),
            ],
        );
        let (config, _) = read_config_and_genesis(&args).expect("parse config with --sora");
        assert!(
            !config.torii.sorafs_storage.enabled,
            "bare --sora must not manufacture an embedded storage-provider role"
        );
        let mut emitter = Emitter::new();
        validate_config_runtime(&mut emitter, &config);
        emitter
            .into_result()
            .expect("bare --sora must satisfy runtime configuration validation");
        let mut expected =
            Config::from_toml_source(TomlSource::inline(minimal_config_table())).expect("default");
        expected.apply_sora_profile();
        assert_eq!(config.nexus.lane_catalog, expected.nexus.lane_catalog);
        assert_eq!(
            config.nexus.dataspace_catalog,
            expected.nexus.dataspace_catalog
        );
        assert_eq!(config.nexus.routing_policy, expected.nexus.routing_policy);
        let lane_aliases: Vec<_> = config
            .nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| lane.alias.as_str())
            .collect();
        assert_eq!(lane_aliases, ["core", "governance", "zk"]);
        let dataspace_aliases: Vec<_> = config
            .nexus
            .dataspace_catalog
            .entries()
            .iter()
            .map(|entry| entry.alias.as_str())
            .collect();
        assert_eq!(dataspace_aliases, ["universal"]);
    }
    #[test]
    fn sora_flag_preserves_explicitly_disabled_sorafs_storage() {
        let mut config_file = NamedTempFile::new().expect("create temp config");
        let mut table = minimal_config_table();
        iroha_config::base::toml::Writer::new(&mut table)
            .write(["sorafs", "storage", "enabled"], false);
        config_file
            .write_all(
                toml::to_string(&toml::Value::Table(table))
                    .expect("render config")
                    .as_bytes(),
            )
            .expect("write config");
        let args = parse_args_from(
            test_build_metadata(),
            [
                "iroha3d",
                "--sora",
                "--config",
                config_file
                    .path()
                    .to_str()
                    .expect("temp config path to string"),
            ],
        );
        let (config, _) =
            read_config_and_genesis(&args).expect("parse config with explicit storage opt-out");
        assert!(
            !config.torii.sorafs_storage.enabled,
            "--sora must not override an explicit operator storage opt-out"
        );
    }
    fn install_storage_signer_fixture_bindings(table: &mut Table) {
        for (role, seed) in [
            ("proof_outcome", 0x84),
            ("repair", 0x85),
            ("reserve", 0x86),
            ("orderbook", 0x87),
        ] {
            let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("fixture role key");
            let authority = AccountId::new(key.public_key().clone())
                .to_i105_for_discriminant(
                    iroha_config::parameters::defaults::common::CHAIN_DISCRIMINANT,
                )
                .expect("fixture role authority");
            let prefix = ["sorafs", "storage", "native_transaction_signers", role];
            for (field, value) in [
                (
                    "handle",
                    format!("software://sorafs/{role}/compliance-fixture"),
                ),
                ("authority", authority),
                ("algorithm", "ed25519".to_owned()),
                ("public_key_hex", hex::encode(key.public_key().to_bytes().1)),
                ("policy_digest_hex", hex::encode([seed; 32])),
            ] {
                iroha_config::base::toml::Writer::new(table)
                    .write([prefix[0], prefix[1], prefix[2], prefix[3], field], value);
            }
            iroha_config::base::toml::Writer::new(table).write(
                [prefix[0], prefix[1], prefix[2], prefix[3], "revision"],
                1_i64,
            );
        }
    }
    #[test]
    fn sora_flag_preserves_explicit_storage_and_rejects_missing_compliance() {
        let mut config_file = NamedTempFile::new().expect("create temp config");
        let mut table = minimal_config_table();
        iroha_config::base::toml::Writer::new(&mut table)
            .write(["sorafs", "storage", "enabled"], true);
        install_storage_signer_fixture_bindings(&mut table);
        config_file
            .write_all(
                toml::to_string(&toml::Value::Table(table))
                    .expect("render config")
                    .as_bytes(),
            )
            .expect("write config");
        let args = parse_args_from(
            test_build_metadata(),
            [
                "iroha3d",
                "--sora",
                "--config",
                config_file
                    .path()
                    .to_str()
                    .expect("temp config path to string"),
            ],
        );
        let (config, _) =
            read_config_and_genesis(&args).expect("parse explicit storage configuration");
        assert!(
            config.torii.sorafs_storage.enabled,
            "--sora must preserve an explicit operator storage request"
        );
        let mut emitter = Emitter::new();
        validate_config_runtime(&mut emitter, &config);
        let error = emitter
            .into_result()
            .expect_err("storage without governed compliance must fail closed");
        assert!(
            format!("{error:?}").contains(
                "sorafs.storage.enabled requires the governed sorafs.gateway.compliance controller"
            ),
            "unexpected storage validation error: {error:?}"
        );
    }
    #[test]
    fn single_lane_config_keeps_canonical_nexus_topology_without_sora_flag() {
        let mut config_file = NamedTempFile::new().expect("create temp config");
        let toml_value = toml::Value::Table(minimal_config_table());
        config_file
            .write_all(
                toml::to_string(&toml_value)
                    .expect("render config")
                    .as_bytes(),
            )
            .expect("write config");
        let args = parse_args_from(
            test_build_metadata(),
            [
                "iroha3d",
                "--config",
                config_file
                    .path()
                    .to_str()
                    .expect("temp config path to string"),
            ],
        );
        let (config, _) = read_config_and_genesis(&args).expect("parse config without --sora");
        assert_eq!(config.nexus.lane_catalog.lane_count().get(), 1);
        assert!(!nexus_topology_is_custom(&config.nexus));
    }
}
#[cfg(test)]
mod accel_tests {
    fn sha256_abc_digest() -> [u8; 32] {
        let mut state = [
            0x6a09_e667_u32,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        let mut block = [0u8; 64];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[63] = 24;
        ivm::sha256_compress(&mut state, &block);
        let mut digest = [0u8; 32];
        for (i, w) in state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        digest
    }
    const SHA256_ABC_EXPECTED: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    struct AccelTestGuard {
        original_config: ivm::AccelerationConfig,
        original_simd_override: Option<ivm::SimdChoice>,
        _simd_lock: std::sync::MutexGuard<'static, ()>,
    }
    impl AccelTestGuard {
        fn new() -> Self {
            let simd_lock = ivm::forced_simd_test_lock();
            let original_config = ivm::acceleration_config();
            let original_simd_override = ivm::set_forced_simd(None);
            Self {
                original_config,
                original_simd_override,
                _simd_lock: simd_lock,
            }
        }
    }
    impl Drop for AccelTestGuard {
        fn drop(&mut self) {
            ivm::set_acceleration_config(self.original_config);
            ivm::set_forced_simd(self.original_simd_override);
        }
    }
    #[test]
    fn accel_config_disables_cuda_parity_holds() {
        let _guard = AccelTestGuard::new();
        ivm::reset_cuda_backend_for_tests();
        let accel = iroha_config::parameters::actual::Acceleration {
            resource_limits: iroha_config::parameters::defaults::accel::RESOURCE_LIMITS,
            enable_simd: true,
            enable_cuda: false,
            enable_metal: true,
            max_gpus: None,
            merkle_min_leaves_gpu: 0,
            merkle_min_leaves_metal: None,
            merkle_min_leaves_cuda: None,
            prefer_cpu_sha2_max_leaves_aarch64: None,
            prefer_cpu_sha2_max_leaves_x86: None,
        };
        super::apply_ivm_acceleration_config(&accel);
        assert!(!ivm::cuda_available(), "CUDA should be disabled by config");
        if ivm::cuda_disabled() || ivm::cuda_available() {
            assert!(ivm::cuda_disabled(), "cuda_disabled flag should be set");
        }
        let mut state = [
            0x6a09_e667_u32,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        let mut block = [0u8; 64];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[63] = 24;
        assert!(
            !ivm::sha256_compress_cuda(&mut state, &block),
            "CUDA helper should report false when disabled"
        );
        assert_eq!(sha256_abc_digest(), SHA256_ABC_EXPECTED);
        let restore = iroha_config::parameters::actual::Acceleration {
            resource_limits: iroha_config::parameters::defaults::accel::RESOURCE_LIMITS,
            enable_simd: true,
            enable_cuda: true,
            enable_metal: true,
            max_gpus: None,
            merkle_min_leaves_gpu: 0,
            merkle_min_leaves_metal: None,
            merkle_min_leaves_cuda: None,
            prefer_cpu_sha2_max_leaves_aarch64: None,
            prefer_cpu_sha2_max_leaves_x86: None,
        };
        super::apply_ivm_acceleration_config(&restore);
        ivm::reset_cuda_backend_for_tests();
    }
    #[test]
    fn accel_config_disables_simd_parity_holds() {
        let _guard = AccelTestGuard::new();
        let original = ivm::acceleration_config();
        let accel = iroha_config::parameters::actual::Acceleration {
            resource_limits: iroha_config::parameters::defaults::accel::RESOURCE_LIMITS,
            enable_simd: false,
            enable_cuda: true,
            enable_metal: true,
            max_gpus: None,
            merkle_min_leaves_gpu: 0,
            merkle_min_leaves_metal: None,
            merkle_min_leaves_cuda: None,
            prefer_cpu_sha2_max_leaves_aarch64: None,
            prefer_cpu_sha2_max_leaves_x86: None,
        };
        super::apply_ivm_acceleration_config(&accel);
        let status = ivm::acceleration_runtime_status();
        assert!(
            !status.simd.configured && !status.simd.available,
            "SIMD backend should be marked unavailable when disabled"
        );
        let result_scalar = ivm::vadd32([9, 8, 7, 6], [1, 2, 3, 4]);
        let restore = iroha_config::parameters::actual::Acceleration {
            resource_limits: original.resource_limits,
            enable_simd: true,
            enable_cuda: original.enable_cuda,
            enable_metal: original.enable_metal,
            max_gpus: original.max_gpus,
            merkle_min_leaves_gpu: original.merkle_min_leaves_gpu.unwrap_or(0),
            merkle_min_leaves_metal: original.merkle_min_leaves_metal,
            merkle_min_leaves_cuda: original.merkle_min_leaves_cuda,
            prefer_cpu_sha2_max_leaves_aarch64: original.prefer_cpu_sha2_max_leaves_aarch64,
            prefer_cpu_sha2_max_leaves_x86: original.prefer_cpu_sha2_max_leaves_x86,
        };
        super::apply_ivm_acceleration_config(&restore);
        let status_enabled = ivm::acceleration_runtime_status();
        assert!(status_enabled.simd.configured);
        let result_simd = ivm::vadd32([9, 8, 7, 6], [1, 2, 3, 4]);
        assert_eq!(
            result_scalar, result_simd,
            "SIMD disablement must not change vector results"
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn accel_config_disables_metal_parity_holds() {
        let _guard = AccelTestGuard::new();
        ivm::reset_metal_backend_for_tests();
        if !ivm::metal_available() {
            return;
        }
        ivm::release_metal_state();
        let pre_dispatches = ivm::MetalKernel::ALL.map(ivm::metal_completed_dispatches);
        let accel = iroha_config::parameters::actual::Acceleration {
            resource_limits: iroha_config::parameters::defaults::accel::RESOURCE_LIMITS,
            enable_simd: true,
            enable_cuda: true,
            enable_metal: false,
            max_gpus: None,
            merkle_min_leaves_gpu: 0,
            merkle_min_leaves_metal: None,
            merkle_min_leaves_cuda: None,
            prefer_cpu_sha2_max_leaves_aarch64: None,
            prefer_cpu_sha2_max_leaves_x86: None,
        };
        super::apply_ivm_acceleration_config(&accel);
        assert!(
            !ivm::metal_available(),
            "Metal should be disabled by config"
        );
        assert!(
            ivm::metal_disabled(),
            "Metal forced-disabled flag should be set"
        );
        let result = ivm::vadd32([1, 2, 3, 4], [4, 3, 2, 1]);
        assert_eq!(result, [5, 5, 5, 5]);
        assert_eq!(
            ivm::MetalKernel::ALL.map(ivm::metal_completed_dispatches),
            pre_dispatches,
            "Metal must not dispatch when disabled"
        );
        assert_eq!(sha256_abc_digest(), SHA256_ABC_EXPECTED);
        let restore = iroha_config::parameters::actual::Acceleration {
            resource_limits: iroha_config::parameters::defaults::accel::RESOURCE_LIMITS,
            enable_simd: true,
            enable_cuda: true,
            enable_metal: true,
            max_gpus: None,
            merkle_min_leaves_gpu: 0,
            merkle_min_leaves_metal: None,
            merkle_min_leaves_cuda: None,
            prefer_cpu_sha2_max_leaves_aarch64: None,
            prefer_cpu_sha2_max_leaves_x86: None,
        };
        super::apply_ivm_acceleration_config(&restore);
        ivm::reset_metal_backend_for_tests();
    }
}
#[cfg(test)]
static INSTRUCTION_REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
fn instruction_registry_test_guard() -> std::sync::MutexGuard<'static, ()> {
    // `iroha_data_model` is linked into this unit-test binary as a normal
    // dependency, so its instruction registry is process-global. Serialize the
    // tests that intentionally clear the registry with the helpers that decode
    // genesis, otherwise parallel test threads can observe an empty registry.
    INSTRUCTION_REGISTRY_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn read_genesis(path: &Path) -> ReportResult<GenesisBlock, ConfigError> {
    read_genesis_with_bytes(path).map(|(genesis, _bytes)| genesis)
}
fn read_genesis_with_bytes(path: &Path) -> ReportResult<(GenesisBlock, Vec<u8>), ConfigError> {
    #[cfg(test)]
    let _registry_guard = instruction_registry_test_guard();
    read_genesis_unlocked_with_bytes(path)
}
fn resolve_norito_max_archive_len(cfg: &Config) -> u64 {
    let requested = cfg.norito.max_archive_len;
    let max_frame_bytes = u64::try_from(cfg.network.max_frame_bytes).unwrap_or(u64::MAX);
    let resolved = requested.max(max_frame_bytes);
    if resolved != requested {
        iroha_logger::warn!(
            target: "config",
            requested,
            max_frame_bytes,
            resolved,
            "Norito max_archive_len too small for the configured network frame; increasing it so accepted frames remain decodable"
        );
    }
    resolved
}
/// Apply Norito operational configuration from config.
fn apply_norito_config(cfg: &Config) {
    let max_archive_len = resolve_norito_max_archive_len(cfg);
    norito::core::set_max_archive_len(max_archive_len);
    norito::core::hw::set_gpu_compression_allowed(cfg.norito.allow_gpu_compression);
}
fn validate_config(config: &Config) -> ReportResult<(), ConfigError> {
    validate_network_frame_runtime_limit(config)?;
    let mut emitter = Emitter::new();
    validate_config_io(&mut emitter, config);
    validate_config_runtime(&mut emitter, config);
    finish_config_validation(emitter)
}
/// Validate only the process resources needed by the read-only emergency runtime.
fn validate_emergency_fast_config(config: &Config) -> ReportResult<(), ConfigError> {
    validate_network_frame_runtime_limit(config)?;
    let mut emitter = Emitter::new();
    validate_config_io(&mut emitter, config);
    finish_config_validation(emitter)
}
fn validate_startup_config(config: &Config) -> ReportResult<(), ConfigError> {
    if config.kura.init_mode == InitMode::Fast {
        validate_emergency_fast_config(config)
    } else {
        validate_config(config)
    }
}
/// Validate configuration without probing or binding any listening socket.
fn validate_config_offline(config: &Config) -> ReportResult<(), ConfigError> {
    validate_network_frame_runtime_limit(config)?;
    let mut emitter = Emitter::new();
    validate_config_static_io(&mut emitter, config);
    validate_config_runtime(&mut emitter, config);
    finish_config_validation(emitter)
}
fn validate_startup_config_offline(config: &Config) -> ReportResult<(), ConfigError> {
    if config.kura.init_mode == InitMode::Fast {
        validate_network_frame_runtime_limit(config)?;
        let mut emitter = Emitter::new();
        validate_config_static_io(&mut emitter, config);
        finish_config_validation(emitter)
    } else {
        validate_config_offline(config)
    }
}
/// Reject frame caps that cannot be encoded before any validation probes bind sockets.
fn validate_network_frame_runtime_limit(config: &Config) -> ReportResult<(), ConfigError> {
    let configured = config.network.max_frame_bytes;
    if configured > iroha_p2p::MAX_ENCRYPTED_FRAME_BYTES {
        return Err(Report::new(
            ConfigError::NetworkFrameSizeExceedsRuntimeLimit { configured },
        ));
    }
    let plaintext_ceiling = iroha_p2p::frame_plaintext_cap(configured);
    for (path, topic_cap) in [
        (
            "network.max_frame_bytes_consensus",
            config.network.max_frame_bytes_consensus,
        ),
        (
            "network.max_frame_bytes_control",
            config.network.max_frame_bytes_control,
        ),
        (
            "network.max_frame_bytes_block_sync",
            config.network.max_frame_bytes_block_sync,
        ),
        (
            "network.max_frame_bytes_tx_gossip",
            config.network.max_frame_bytes_tx_gossip,
        ),
        (
            "network.max_frame_bytes_peer_gossip",
            config.network.max_frame_bytes_peer_gossip,
        ),
        (
            "network.max_frame_bytes_health",
            config.network.max_frame_bytes_health,
        ),
        (
            "network.max_frame_bytes_connect",
            config.network.max_frame_bytes_connect,
        ),
        (
            "network.max_frame_bytes_other",
            config.network.max_frame_bytes_other,
        ),
    ] {
        if topic_cap > plaintext_ceiling {
            return Err(Report::new(
                ConfigError::NetworkTopicFrameSizeExceedsPlaintextLimit {
                    path,
                    configured: topic_cap,
                    plaintext_ceiling,
                    encrypted_cap: configured,
                },
            ));
        }
    }
    Ok(())
}
fn finish_config_validation(emitter: Emitter<ConfigError>) -> ReportResult<(), ConfigError> {
    if let Err(report) = emitter.into_result() {
        let mut collected: Vec<ConfigError> = report
            .frames()
            .filter_map(|frame| frame.downcast_ref::<ConfigError>())
            .cloned()
            .collect();
        if let Some(mut aggregated) = collected.pop().map(Report::new) {
            while let Some(error) = collected.pop() {
                aggregated = aggregated.change_context(error);
            }
            return Err(aggregated.change_context(ConfigError::ParseConfig));
        }
        return Err(Report::new(ConfigError::ParseConfig));
    }
    Ok(())
}
fn validate_config_io(emitter: &mut Emitter<ConfigError>, config: &Config) {
    // These cause race condition in tests, due to them actually binding TCP listeners
    // Since these validations are primarily for the convenience of the end user,
    // it seems a fine compromise to run it only in release mode
    #[cfg(not(test))]
    {
        validate_try_bind_address(emitter, &config.network.address);
        validate_try_bind_address(emitter, &config.torii.address);
    }
    validate_config_static_io(emitter, config);
}
fn validate_config_static_io(emitter: &mut Emitter<ConfigError>, config: &Config) {
    validate_directory_path(emitter, &config.kura.store_dir);
    // maybe validate only if snapshot mode is enabled
    validate_directory_path(emitter, &config.snapshot.store_dir);
    if config.network.address.value() == config.torii.address.value() {
        emitter.emit(
            Report::new(ConfigError::SameNetworkAndToriiAddrs)
                .attach(config.network.address.clone().into_attachment())
                .attach(config.torii.address.clone().into_attachment()),
        );
    }
}
fn validate_config_runtime(emitter: &mut Emitter<ConfigError>, config: &Config) {
    let sorafs_storage_enabled = config.torii.sorafs_storage.enabled;
    let sorafs_gateway_compliance_enabled = config.torii.sorafs_gateway.compliance.is_some();
    if sorafs_storage_enabled && !sorafs_gateway_compliance_enabled {
        emitter.emit(Report::new(ConfigError::SorafsStorageComplianceRequired));
    }
    if !sorafs_storage_enabled
        && (config.torii.sorafs_gateway.acme.enabled || sorafs_gateway_compliance_enabled)
    {
        emitter.emit(Report::new(ConfigError::SorafsGatewayRequiresStorage));
    }
    #[cfg(not(feature = "telemetry"))]
    if config.telemetry.is_some() {
        emitter.emit(
            Report::new(ConfigError::InactiveTelemetryConfiguration)
                .attach("`telemetry` requires a binary built with the `telemetry` feature"),
        );
    }
    #[cfg(feature = "telemetry")]
    {
        if config.telemetry.is_some() && !config.telemetry_profile.metrics_enabled() {
            emitter.emit(
                Report::new(ConfigError::InactiveTelemetryConfiguration)
                    .attach("`telemetry` is configured while telemetry_profile disables telemetry"),
            );
        }
        let telegram_requested = config.telemetry.as_ref().is_some_and(|telemetry| {
            telemetry.telegram_bot_key.is_some() || telemetry.telegram_chat_id.is_some()
        });
        #[cfg(not(feature = "telegram-alerts"))]
        if telegram_requested {
            emitter.emit(
                Report::new(ConfigError::InactiveTelemetryConfiguration).attach(
                    "Telegram alert settings require a binary built with `telegram-alerts`",
                ),
            );
        }
        #[cfg(feature = "telegram-alerts")]
        if telegram_requested && !config.telemetry_profile.developer_outputs_enabled() {
            emitter.emit(
                Report::new(ConfigError::InactiveTelemetryConfiguration)
                    .attach("Telegram alerts require the Developer or Full telemetry profile"),
            );
        }
    }
    #[cfg(not(feature = "dev-telemetry"))]
    if config.dev_telemetry.out_file.is_some() {
        emitter.emit(
            Report::new(ConfigError::InactiveTelemetryConfiguration)
                .attach("`dev_telemetry.out_file` requires a binary built with `dev-telemetry`"),
        );
    }
    #[cfg(feature = "dev-telemetry")]
    if let Some(path) = &config.dev_telemetry.out_file {
        if !config.telemetry_profile.developer_outputs_enabled() {
            emitter.emit(
                Report::new(ConfigError::InactiveTelemetryConfiguration).attach(
                    "`dev_telemetry.out_file` requires the Developer or Full telemetry profile",
                ),
            );
        }
        if path.value().parent().is_none() {
            emitter.emit(
                Report::new(ConfigError::TelemetryOutFileIsRootOrEmpty)
                    .attach(path.clone().into_attachment().display_path()),
            );
        }
        if path.value().is_dir() {
            emitter.emit(
                Report::new(ConfigError::TelemetryOutFileIsDir)
                    .attach(path.clone().into_attachment().display_path()),
            );
        }
    }
    if config.telemetry.is_none()
        && config.dev_telemetry.out_file.is_none()
        && (config.telemetry_integrity.state_dir.is_some()
            || config.telemetry_integrity.signing_key.is_some()
            || config.telemetry_integrity.signing_key_id.is_some())
    {
        emitter.emit(
            Report::new(ConfigError::InactiveTelemetryConfiguration).attach(
                "telemetry integrity state/signing settings require a configured telemetry sink",
            ),
        );
    }
    if config.sumeragi.role == iroha_config::parameters::actual::NodeRole::Validator {
        if !config.confidential.enabled {
            emitter.emit(
                Report::new(ConfigError::ConfidentialDisabledForValidator).attach(
                    "validators must enable confidential verification or downgrade the node role to `Observer`",
                ),
            );
        }
        if config.confidential.assume_valid {
            emitter.emit(
                Report::new(ConfigError::ConfidentialAssumeValidForValidator).attach(
                    "validators cannot run with confidential observer mode; set `confidential.assume_valid = false`",
                ),
            );
        }
    }
}
fn validate_directory_path(emitter: &mut Emitter<ConfigError>, path: &WithOrigin<PathBuf>) {
    #[derive(Debug)]
    struct InvalidDirPathError {
        path: PathBuf,
    }
    impl core::fmt::Display for InvalidDirPathError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "expected path to be either non-existing or a directory, but it points to an existing file: {}",
                self.path.display()
            )
        }
    }
    impl std::error::Error for InvalidDirPathError {}
    if path.value().is_file() {
        emitter.emit(
            Report::new(InvalidDirPathError {
                path: path.value().clone(),
            })
            .attach(path.clone().into_attachment().display_path())
            .change_context(ConfigError::InvalidDirPath),
        );
    }
}
#[cfg(not(test))]
fn validate_try_bind_address(_emitter: &mut Emitter<ConfigError>, value: &WithOrigin<SocketAddr>) {
    use std::net::TcpListener;
    if let Err(err) = TcpListener::bind(value.value()) {
        iroha_logger::warn!(addr = %value.value(), raw = ?err.raw_os_error(), err = ?err, "Skipping bind validation after failure");
    }
}
/// Configures globals of [`error_stack::Report`]
fn configure_reports(args: &Args) {
    use error_stack::{Report, fmt::ColorMode};
    use std::panic::Location;
    Report::set_color_mode(if args.terminal_colors {
        ColorMode::Color
    } else {
        ColorMode::None
    });
    // neither devs nor users benefit from it
    Report::install_debug_hook::<Location>(|_, _| {});
}
/// Run the stock daemon launcher.
///
/// The stock binaries resolve supported runtime-only bindings through a
/// configured authenticated local broker running under the same effective service UID.
/// The broker is not contacted when the validated configuration contains no
/// runtime-provider bindings.
pub fn main_entry(build: CompiledBuildMetadata) {
    #[cfg(unix)]
    if external_software_signer::dispatch_beacon_custody_preparation_if_requested() {
        return;
    }
    soracloud_runtime::dispatch_inrou_internal_launcher_if_requested();
    let _ = std::hint::black_box(build.sealed_source_commit());
    if let Err(report) = run_main(build, None, None) {
        eprintln!("{report:?}");
        std::process::exit(1);
    }
}
/// Run the standard CLI launcher with a deployment-owned provider registry.
///
/// An external deployment binary can call this function after constructing a
/// registry backed by a reviewed deployment-owned runtime. Registry selection
/// is an explicit launcher decision; no environment or config value
/// dynamically loads executable provider code.
///
/// Inrou V1 hosting is intentionally unavailable through external wrapper
/// executables because its child self-exec dispatcher must run as the wrapper's
/// first instruction. Use the stock `iroha3d` or `iroha3d_taira` binary for an
/// Inrou host.
///
/// # Errors
///
/// Returns a launcher error if configuration, provider resolution, subsystem
/// startup, or supervised execution fails.
pub fn run_with_runtime_provider_registry(
    build: CompiledBuildMetadata,
    registry: &dyn IrohaRuntimeProviderRegistryV1,
) -> ReportResult<(), MainError> {
    run_main(build, Some(registry), None)
}
/// Deployment-launcher guard evaluated over the parsed daemon configuration.
type IrohaLauncherConfigGuardV1 = fn(&Config) -> Result<(), String>;
/// Run the standard CLI launcher with a deployment-owned configuration guard.
///
/// The guard runs after the complete configuration is parsed and before
/// offline validation, runtime-provider resolution, Tokio construction, or
/// node startup. This entrypoint is used by deployment launchers whose
/// `--check-config` operation must enforce a pinned public network profile
/// without opening runtime-only credentials.
pub(crate) fn run_with_config_guard(
    build: CompiledBuildMetadata,
    guard: IrohaLauncherConfigGuardV1,
) -> ReportResult<(), MainError> {
    run_main_with_config_guard(build, None, None, Some(guard))
}
/// Run the standard CLI launcher with a deployment-owned provider registry and
/// configuration guard.
///
/// The guard remains authoritative over the parsed public network profile,
/// while the registry remains authoritative over runtime-only providers.
pub(crate) fn run_with_runtime_provider_registry_and_config_guard(
    build: CompiledBuildMetadata,
    registry: &dyn IrohaRuntimeProviderRegistryV1,
    guard: IrohaLauncherConfigGuardV1,
) -> ReportResult<(), MainError> {
    run_main_with_config_guard(build, Some(registry), None, Some(guard))
}
/// Run the standard CLI launcher with a deployment-owned private Musubi publication factory.
///
/// The caller supplies a one-shot factory which receives the exact daemon-owned finalized-state,
/// transaction-queue, and `SoraFS` handles only after trusted startup replay. The factory must
/// assemble the complete private HTTPS runner, including its durable clock and journal, receipt
/// signer, and admitted `SoraFS` backends. The launcher transfers that opaque factory into the
/// daemon supervisor without requiring an unrelated runtime-provider registry. It never exposes
/// the private routes through Torii or reads service credentials from argv or node configuration.
/// An unexpected private-runner exit is fatal to the same supervisor that owns the node.
/// Inrou V1 hosting remains restricted to the stock `iroha3d` and
/// `iroha3d_taira` first-instruction launchers.
///
/// # Errors
///
/// Returns a launcher error if configuration, subsystem startup, or supervised execution fails.
pub fn run_with_musubi_publication(
    build: CompiledBuildMetadata,
    factory: Box<dyn musubi_publication_service::MusubiPublicationPrivateServiceFactoryV1>,
) -> ReportResult<(), MainError> {
    run_main(build, None, Some(factory))
}
/// Run the standard CLI launcher with deployment-owned runtime providers and a private Musubi
/// publication factory.
///
/// The one-shot factory receives the exact daemon-owned finalized-state, transaction-queue, and
/// `SoraFS` handles only after trusted startup replay. It must assemble the complete private HTTPS
/// runner, including its durable clock and journal, receipt signer, and admitted `SoraFS` backends,
/// while retaining every credential inside deployment-owned adapters. The launcher only transfers
/// that opaque factory into the daemon supervisor; it never exposes the private routes through
/// Torii or reads service credentials from argv or node configuration. An unexpected private-runner
/// exit is fatal to the same supervisor that owns the node.
/// Inrou V1 hosting remains restricted to the stock `iroha3d` and
/// `iroha3d_taira` first-instruction launchers.
///
/// # Errors
///
/// Returns a launcher error if configuration, provider resolution, subsystem startup, or
/// supervised execution fails.
pub fn run_with_runtime_provider_registry_and_musubi_publication(
    build: CompiledBuildMetadata,
    registry: &dyn IrohaRuntimeProviderRegistryV1,
    factory: Box<dyn musubi_publication_service::MusubiPublicationPrivateServiceFactoryV1>,
) -> ReportResult<(), MainError> {
    run_main(build, Some(registry), Some(factory))
}
fn parse_fastpq_execution_mode(value: &str) -> Result<FastpqExecutionMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "cpu" => Ok(FastpqExecutionMode::Cpu),
        "gpu" => Ok(FastpqExecutionMode::Gpu),
        _ => Err("expected MODE to be one of: cpu, gpu".to_string()),
    }
}
fn parse_fastpq_poseidon_mode(value: &str) -> Result<FastpqPoseidonMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "cpu" => Ok(FastpqPoseidonMode::Cpu),
        "gpu" => Ok(FastpqPoseidonMode::Gpu),
        _ => Err("expected MODE to be one of: cpu, gpu".to_string()),
    }
}
fn args_command(build: CompiledBuildMetadata) -> clap::Command {
    Args::command().version(build.version())
}
fn parse_args(build: CompiledBuildMetadata) -> Args {
    parse_args_from(build, env::args_os())
}
fn parse_args_from<I, T>(build: CompiledBuildMetadata, args: I) -> Args
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut iter = args.into_iter().map(Into::into);
    let mut filtered = Vec::new();
    if let Some(binary) = iter.next() {
        filtered.push(binary);
    } else {
        filtered.push(OsString::from("iroha3d"));
    }
    filtered.extend(iter.filter_map(|arg| {
        let display = arg.to_string_lossy();
        let trimmed = display.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.len() == display.len() {
            return Some(arg);
        }
        match display {
            Cow::Borrowed(_) => Some(OsString::from(trimmed)),
            Cow::Owned(_) => Some(arg),
        }
    }));
    let matches = args_command(build).get_matches_from(filtered);
    Args::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}
#[cfg(test)]
fn test_build_metadata() -> CompiledBuildMetadata {
    CompiledBuildMetadata::from_compiled_parts(
        env!("CARGO_PKG_VERSION"),
        Some("local-fast-build"),
        None,
        None,
        None,
        None,
    )
}
#[cfg(feature = "telemetry")]
#[derive(Clone)]
struct FastpqDeviceLabels {
    device_class: Arc<str>,
    chip_family: Arc<str>,
    gpu_kind: Arc<str>,
}
#[cfg(feature = "telemetry")]
impl FastpqDeviceLabels {
    fn from_config(config: &iroha_config::parameters::actual::Fastpq) -> Self {
        Self {
            device_class: normalize_fastpq_label(config.device_class.clone(), "unknown"),
            chip_family: normalize_fastpq_label(config.chip_family.clone(), "unknown"),
            gpu_kind: normalize_fastpq_label(config.gpu_kind.clone(), "unknown"),
        }
    }
}
#[cfg(feature = "telemetry")]
fn normalize_fastpq_label(label: Option<String>, fallback: &str) -> Arc<str> {
    label
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        })
        .map_or_else(|| Arc::from(fallback), Arc::from)
}
#[cfg(feature = "telemetry")]
fn install_fastpq_execution_mode_probe(labels: &FastpqDeviceLabels) {
    let telemetry_labels = labels.clone();
    fastpq_prover::set_execution_mode_observer(move |requested, resolved, backend| {
        let backend_label = backend.map_or("none", |kind| kind.as_str());
        let metrics = iroha_telemetry::metrics::global_or_default();
        metrics.record_fastpq_execution_mode(
            requested.as_str(),
            resolved.as_str(),
            backend_label,
            telemetry_labels.device_class.as_ref(),
            telemetry_labels.chip_family.as_ref(),
            telemetry_labels.gpu_kind.as_ref(),
        );
    });
}
#[cfg(feature = "fastpq-gpu")]
fn preflight_fastpq_bn254_poseidon_words(config: &iroha_config::parameters::actual::Fastpq) {
    if !fastpq_poseidon_word_preflight_enabled(config) {
        iroha_logger::debug!(
            target: "fastpq",
            "BN254 Poseidon word-batch GPU preflight skipped by FASTPQ config"
        );
        return;
    }
    if fastpq_prover::preflight_bn254_poseidon_word_batches() {
        iroha_logger::info!(
            target: "fastpq",
            "BN254 Poseidon word-batch GPU preflight passed"
        );
    } else {
        iroha_logger::debug!(
            target: "fastpq",
            "BN254 Poseidon word-batch GPU preflight unavailable; scalar fallback remains active"
        );
    }
}
#[cfg(feature = "fastpq-gpu")]
fn fastpq_poseidon_word_preflight_enabled(
    config: &iroha_config::parameters::actual::Fastpq,
) -> bool {
    match config.poseidon_mode {
        FastpqPoseidonMode::Cpu => false,
        FastpqPoseidonMode::Gpu => true,
    }
}
#[cfg(feature = "telemetry")]
fn install_fastpq_poseidon_probe(labels: &FastpqDeviceLabels) {
    let telemetry_labels = labels.clone();
    fastpq_prover::set_poseidon_pipeline_observer(move |policy, path, _backend| {
        let metrics = iroha_telemetry::metrics::global_or_default();
        metrics.record_fastpq_poseidon_mode(
            policy.requested().as_str(),
            policy.resolved().as_str(),
            path,
            telemetry_labels.device_class.as_ref(),
            telemetry_labels.chip_family.as_ref(),
            telemetry_labels.gpu_kind.as_ref(),
        );
    });
}
#[cfg(feature = "telemetry")]
fn install_fastpq_gpu_event_probe(labels: &FastpqDeviceLabels) {
    let telemetry_labels = labels.clone();
    fastpq_prover::set_poseidon_gpu_event_observer(move |accelerator, event, reason, backend| {
        let gpu_kind =
            backend.map_or_else(|| telemetry_labels.gpu_kind.as_ref(), |kind| kind.as_str());
        let metrics = iroha_telemetry::metrics::global_or_default();
        match event {
            "disabled" => metrics.inc_fastpq_gpu_disable(
                accelerator,
                reason,
                telemetry_labels.device_class.as_ref(),
                telemetry_labels.chip_family.as_ref(),
                gpu_kind,
            ),
            "sampled_parity_failure" => metrics.inc_fastpq_gpu_parity_failure(
                accelerator,
                reason,
                telemetry_labels.device_class.as_ref(),
                telemetry_labels.chip_family.as_ref(),
                gpu_kind,
            ),
            _ => {}
        }
    });
}
#[cfg(all(feature = "telemetry", feature = "fastpq-gpu", target_os = "macos"))]
fn install_fastpq_queue_probe(labels: FastpqDeviceLabels) {
    use fastpq_prover::{
        enable_lde_host_stats, enable_queue_depth_stats, snapshot_queue_depth_stats,
        take_lde_host_stats,
    };
    use iroha_telemetry::metrics::{
        FastpqMetalQueueLaneSample, FastpqMetalQueueSample, global_or_default,
    };
    use std::{sync::Arc, thread, time::Duration};
    enable_queue_depth_stats(true);
    enable_lde_host_stats(true);
    let labels = Arc::new(labels);
    thread::Builder::new()
        .name("fastpq-queue-telemetry".into())
        .spawn(move || {
            let metrics = global_or_default();
            let mut lane_buffer = Vec::new();
            loop {
                thread::sleep(Duration::from_secs(5));
                if let Some(stats) = snapshot_queue_depth_stats() {
                    lane_buffer.clear();
                    for lane in &stats.queues {
                        lane_buffer.push(FastpqMetalQueueLaneSample {
                            index: lane.index as usize,
                            dispatch_count: u64::from(lane.dispatch_count),
                            max_in_flight: u64::from(lane.max_in_flight),
                            busy_ms: lane.busy_ms,
                            overlap_ms: lane.overlap_ms,
                        });
                    }
                    let sample = FastpqMetalQueueSample {
                        limit: u64::from(stats.limit),
                        max_in_flight: u64::from(stats.max_in_flight),
                        dispatch_count: u64::from(stats.dispatch_count),
                        window_ms: stats.window_ms,
                        busy_ms: stats.busy_ms,
                        overlap_ms: stats.overlap_ms,
                        lanes: &lane_buffer,
                    };
                    metrics.record_fastpq_metal_queue_stats(
                        labels.device_class.as_ref(),
                        labels.chip_family.as_ref(),
                        labels.gpu_kind.as_ref(),
                        &sample,
                    );
                }
                while let Some(stats) = take_lde_host_stats() {
                    metrics.record_fastpq_zero_fill(
                        labels.device_class.as_ref(),
                        labels.chip_family.as_ref(),
                        labels.gpu_kind.as_ref(),
                        stats.zero_fill_ms,
                        stats.zero_fill_bytes as u64,
                    );
                }
            }
        })
        .expect("spawn FASTPQ Metal queue telemetry thread");
}
fn run_main(
    build: CompiledBuildMetadata,
    runtime_provider_registry: Option<&dyn IrohaRuntimeProviderRegistryV1>,
    musubi_publication_factory: Option<
        Box<dyn musubi_publication_service::MusubiPublicationPrivateServiceFactoryV1>,
    >,
) -> ReportResult<(), MainError> {
    run_main_with_config_guard(
        build,
        runtime_provider_registry,
        musubi_publication_factory,
        None,
    )
}
fn run_main_with_config_guard(
    build: CompiledBuildMetadata,
    runtime_provider_registry: Option<&dyn IrohaRuntimeProviderRegistryV1>,
    musubi_publication_factory: Option<
        Box<dyn musubi_publication_service::MusubiPublicationPrivateServiceFactoryV1>,
    >,
    launcher_config_guard: Option<IrohaLauncherConfigGuardV1>,
) -> ReportResult<(), MainError> {
    let args = parse_args(build);
    let lang = i18n::detect_language(args.language.as_deref());
    i18n::init(lang);
    configure_reports(&args);
    if args.startup.trace_config {
        iroha_config::enable_tracing()
            .change_context(MainError::TraceConfigSetup)
            .attach("was enabled by `--trace-config` argument")?;
    }
    // Ensure the instruction registry is initialized **before** we attempt to
    // read and decode the genesis block. Without this call, decoding the
    // embedded `InstructionBox` values would panic with "instruction registry is not initialized".
    init_genesis_instruction_registry();
    let (config, genesis) =
        read_config_and_genesis(&args)
            .change_context(MainError::Config)
            .attach_with(|| {
            args.config.as_ref().map_or_else(
                || "`--config` arg was not set, therefore development environment inputs and built-in defaults are in use".to_owned(),
                |path| format!("config path is specified by `--config` arg: {}", path.display()),
            )
        })?;
    let emergency_fast = config.kura.init_mode == InitMode::Fast;
    if let Some(guard) = launcher_config_guard {
        guard(&config).map_err(|error| {
            Report::new(MainError::Config).attach(format!(
                "deployment launcher rejected parsed configuration: {error}"
            ))
        })?;
    }
    if args.startup.check_storage {
        return compatibility_probe::run_check_storage(&config);
    }
    if args.startup.check_config {
        let validated_genesis = validate_config_and_genesis_for_check(
            &config,
            genesis.as_ref(),
            args.startup
                .require_genesis_inrou_deployment_authority
                .as_deref(),
        )?;
        if args.startup.json {
            let compatibility = compatibility_probe::config_compatibility_v1(
                &config,
                genesis.as_ref().zip(validated_genesis.as_ref()),
                build,
            )?;
            let json = norito::json::to_json(&compatibility)
                .map_err(|error| Report::new(MainError::Config).attach(error.to_string()))?;
            println!("{json}");
        } else if genesis.is_some() {
            println!("Ready: configuration and available genesis are valid");
        } else {
            println!(
                "Pending: static configuration is valid; genesis/bootstrap state is not locally available"
            );
        }
        return Ok(());
    }
    // Keep pure configuration and signed-input admission ahead of storage. Strict startup
    // then executes exactly once into its real native owner before resolving providers.
    validate_startup_config_offline(&config).change_context(MainError::Config)?;
    // A `data_dir` node started by the stock launcher reads its runtime secrets from fixed files
    // under `<data_dir>/secrets/`; deployment launchers keep their own registries.
    let node_secrets_launch =
        config.data_dir.is_some() && !emergency_fast && runtime_provider_registry.is_none();
    if let Some(local_genesis) = genesis.as_ref() {
        if emergency_fast {
            // Emergency Fast preserves its existing supplied-genesis offline admission;
            // the runtime itself stays read-only and never starts native replay.
            let (authenticated, _) =
                validate_available_genesis_for_check(&config, local_genesis, None)?;
            if authenticated.network_id
                != NetworkId::from_genesis_hash(config.genesis.expected_hash)
            {
                return Err(Report::new(MainError::Config)
                    .attach("signed genesis belongs to another network"));
            }
        } else {
            validate_available_genesis_inputs(&config, local_genesis)?;
        }
    }
    // Pure projection still fails before opening storage or resolving executable providers.
    if !emergency_fast {
        IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .map_err(Report::new)
            .change_context(MainError::Config)
            .attach("failed to project deployment runtime-provider bindings")?;
    }
    let musubi_publication_factory = if emergency_fast {
        None
    } else {
        musubi_publication_factory
    };
    #[cfg(feature = "telemetry")]
    if !emergency_fast && config.telemetry_profile.expensive_metrics_enabled() {
        let fastpq_device_labels = FastpqDeviceLabels::from_config(&config.zk.fastpq);
        install_fastpq_execution_mode_probe(&fastpq_device_labels);
        install_fastpq_poseidon_probe(&fastpq_device_labels);
        install_fastpq_gpu_event_probe(&fastpq_device_labels);
        #[cfg(all(feature = "fastpq-gpu", target_os = "macos"))]
        install_fastpq_queue_probe(fastpq_device_labels.clone());
    }
    // Concurrency configuration: set global Rayon pool and IVM scheduler limits.
    let min = if config.concurrency.scheduler_min_threads == 0 {
        // auto (physical cores) — defer to IVM internals
        0
    } else {
        config.concurrency.scheduler_min_threads
    };
    let max = if config.concurrency.scheduler_max_threads == 0 {
        // auto
        0
    } else {
        config.concurrency.scheduler_max_threads
    };
    // Build Tokio runtime with a conservative number of worker threads to avoid
    // oversubscription with the IVM scheduler. Keep a slightly higher minimum
    // to prevent HTTP/p2p tasks from starving under consensus body/chunk load, and use the
    // available parallelism as the auto baseline instead of a fixed floor.
    let auto_budget = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4);
    let budget = if max > 0 {
        max
    } else if min > 0 {
        min
    } else {
        auto_budget
    };
    let tokio_workers = budget.clamp(4, 16);
    // Fast intentionally skips the general runtime validator. Do not feed its unvalidated
    // stack-size knob into the runtime builder; use the repository's bounded default instead.
    let tokio_stack_bytes = if emergency_fast {
        iroha_config::parameters::actual::Concurrency::from_defaults().tokio_stack_bytes
    } else {
        config.concurrency.tokio_stack_bytes
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(tokio_workers)
        .thread_stack_size(tokio_stack_bytes)
        .enable_all()
        .build()
        .map_err(Report::from)
        .change_context(MainError::IrohaStart)?;
    let logger = init_startup_logger(&rt, config.logger.clone())?;
    let result = match prepare_with_runtime_deps(&rt, config, genesis, |config| {
        let runtime_deps = if emergency_fast {
            iroha_logger::warn!(
                "emergency Fast startup skipped deployment runtime-provider projection and resolution"
            );
            IrohaRuntimeDeps::default()
        } else if node_secrets_launch {
            resolve_node_secrets_runtime_deps(&config)?
        } else {
            let stock_runtime_provider_registry = if runtime_provider_registry.is_none() {
                let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
                    .map_err(Report::new)
                    .change_context(MainError::Config)
                    .attach("failed to project deployment runtime-provider bindings")?;
                (!bindings.is_empty()).then(|| {
                    runtime_provider_broker::StockRuntimeProviderBrokerRegistryV1::new(
                        config.runtime_provider_broker.endpoint_path.clone(),
                    )
                })
            } else {
                None
            };
            let runtime_provider_registry = runtime_provider_registry.or_else(|| {
                stock_runtime_provider_registry.as_ref().map(|registry| {
                    let registry: &dyn IrohaRuntimeProviderRegistryV1 = registry;
                    registry
                })
            });
            runtime_provider_registry::resolve_runtime_deps(&config, runtime_provider_registry)
                .map_err(Report::new)
                .change_context(MainError::Config)
                .attach("failed to resolve deployment runtime-provider bindings")?
        };
        #[cfg(feature = "test-network-parliament-signers")]
        let runtime_deps = {
            if emergency_fast {
                runtime_deps
            } else {
                if runtime_deps.sumeragi_global_beacon_partial_signer.is_some()
                    || runtime_deps.parliament_tle_partial_release_signer.is_some()
                {
                    return Err(Report::new(MainError::Config).attach(
                        "the test-network Parliament signers reject a second injected provider",
                    ));
                }
                let ordered_roster =
                    filter_validators_from_trusted(config.common.trusted_peers.value());
                let test_network_id = NetworkId::from_genesis_hash(config.genesis.expected_hash);
                let beacon_signer = iroha_core::beacon::parliament_test_network_signer::
                TestNetworkParliamentBeaconPartialSignerV1::try_new(
                    test_network_id,
                    ordered_roster.clone(),
                    &config.common.peer.id,
                    &iroha_allocation::AllocationBudget::new(
                        config.runtime_provider_broker.credential_max_memory_bytes.get(),
                    ),
                )
                .map_err(|_| Report::new(MainError::Config))
                .attach(
                    "failed to bind the feature-isolated Parliament beacon signer to the exact local validator seat",
                )?;
                let beacon_signer: Option<
                    Arc<dyn iroha_core::beacon::GlobalThresholdBeaconPartialSignerV1>,
                > = match args.test_network_parliament_beacon_signer_mode {
                    TestNetworkParliamentBeaconSignerMode::Valid => Some(Arc::new(beacon_signer)),
                    TestNetworkParliamentBeaconSignerMode::Absent => None,
                    TestNetworkParliamentBeaconSignerMode::Invalid => {
                        Some(Arc::new(beacon_signer.with_deliberately_invalid_outbound()))
                    }
                };
                let tle_signer = iroha_core::tle_release::parliament_test_network_signer::
                TestNetworkParliamentTlePartialReleaseSignerV1::try_new(
                    test_network_id,
                    ordered_roster,
                    &config.common.peer.id,
                )
                .map_err(|_| Report::new(MainError::Config))
                .attach(
                    "failed to bind the feature-isolated Parliament TLE signer to the exact local validator seat",
                )?;
                let runtime_deps =
                    runtime_deps.with_parliament_tle_partial_release_signer(Arc::new(tle_signer));
                if let Some(beacon_signer) = beacon_signer {
                    runtime_deps.with_sumeragi_global_beacon_partial_signer(beacon_signer)
                } else {
                    runtime_deps
                }
            }
        };
        Ok(runtime_deps.with_sumeragi_fresh_key_assertion(args.startup.sumeragi_assert_fresh_key))
    }) {
        Ok((prepared, runtime_deps)) => rt.block_on(run_node(
            build,
            prepared,
            logger,
            runtime_deps,
            musubi_publication_factory,
        )),
        Err(error) => Err(error),
    };
    rt.shutdown_timeout(NODE_RUNTIME_SHUTDOWN_TIMEOUT);
    result
}

/// Spawn the logger on the node's runtime without entering the later provider boundary.
fn init_startup_logger(
    runtime: &tokio::runtime::Runtime,
    config: iroha_logger::Config,
) -> ReportResult<LoggerHandle, MainError> {
    let _entered = runtime.enter();
    iroha_logger::init_global(config).map_err(|error| Report::new(MainError::Logger).attach(error))
}

/// Hold actual native preparation across the out-of-Tokio provider boundary.
///
/// Provider failure may leave valid genesis durably retained. It never leaves the prepared
/// executor, query pruner, NTS reservation or storage custody running after this function returns.
fn prepare_with_runtime_deps(
    runtime: &tokio::runtime::Runtime,
    config: Config,
    genesis: Option<GenesisBlock>,
    resolve: impl FnOnce(&Config) -> ReportResult<IrohaRuntimeDeps, MainError>,
) -> ReportResult<(PreparedStartup, IrohaRuntimeDeps), MainError> {
    let prepared = runtime
        .block_on(PreparedStartup::prepare(config, genesis))
        .change_context(MainError::IrohaStart)?;
    // Deliberately outside every runtime enter/block_on guard. This synchronous borrowed
    // deployment API may perform blocking I/O or create its own runtime.
    match resolve(prepared.config()) {
        Ok(dependencies) => Ok((prepared, dependencies)),
        Err(error) => match runtime.block_on(prepared.close()) {
            Ok(()) => Err(error),
            Err(cleanup) => {
                Err(error.attach(format!("prepared startup cleanup failed: {cleanup:?}")))
            }
        },
    }
}

/// Validate configuration and any locally available genesis without mutating durable state,
/// returning the authenticated genesis bootstrap when the signed genesis is available.
fn validate_config_and_genesis_for_check(
    config: &Config,
    genesis: Option<&GenesisBlock>,
    required_inrou_deployment_authority: Option<&str>,
) -> ReportResult<Option<crate::authenticated_genesis::AuthenticatedGenesis>, MainError> {
    let _discriminant = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        *config.common.chain_discriminant.value(),
    );
    let required_authority = required_inrou_deployment_authority
        .map(|literal| {
            let account = AccountId::parse_encoded(literal).map_err(|_| {
                Report::new(MainError::Config)
                    .attach("required Inrou deployment authority must be a canonical account ID for the configured chain")
            })?;
            if account.to_string() != literal {
                return Err(Report::new(MainError::Config)
                    .attach("required Inrou deployment authority must be a canonical account ID for the configured chain"));
            }
            Ok(account)
        })
        .transpose()?;
    if required_authority.is_some() && genesis.is_none() {
        return Err(Report::new(MainError::Config).attach(
            "required Inrou deployment authority cannot be qualified without the signed genesis",
        ));
    }
    validate_config_offline(config).change_context(MainError::Config)?;
    IrohaRuntimeProviderBindingsV1::try_from_config(config)
        .map_err(Report::new)
        .change_context(MainError::Config)
        .attach("failed to validate the public runtime-provider binding catalog")?;
    genesis
        .map(|genesis| {
            validate_available_genesis_for_check(config, genesis, required_authority.as_ref())
                .map(|(bootstrap, _)| bootstrap)
        })
        .transpose()
}

/// Resolve the runtime secrets of a `data_dir` node for a real start.
///
/// Opens the fixed files under `<data_dir>/secrets/` through [`node_secrets::NodeSecretsV1`] and
/// resolves the Soracloud runtime signer and the global-beacon partial signer.
#[cfg(feature = "daemon")]
fn resolve_node_secrets_runtime_deps(config: &Config) -> ReportResult<IrohaRuntimeDeps, MainError> {
    let secrets_error = |error: node_secrets::NodeSecretsErrorV1| {
        Report::new(MainError::Config).attach(error.to_string())
    };
    let credential_budget = iroha_allocation::AllocationBudget::new(
        config
            .runtime_provider_broker
            .credential_max_memory_bytes
            .get(),
    );
    let secrets = node_secrets::NodeSecretsV1::open(config, &credential_budget)
        .map_err(|error| Report::new(error).change_context(MainError::Config))?
        .ok_or_else(|| Report::new(MainError::Config).attach("node secrets require data_dir"))?;
    secrets.resolve_runtime_deps(config).map_err(secrets_error)
}
/// A build without daemon providers cannot resolve fixed-secret runtime providers.
#[cfg(not(feature = "daemon"))]
fn resolve_node_secrets_runtime_deps(
    _config: &Config,
) -> ReportResult<IrohaRuntimeDeps, MainError> {
    Err(Report::new(MainError::Config).attach("data_dir node secrets require the daemon feature"))
}
struct GenesisStaticInputs {
    authority: AccountId,
    mode: iroha_data_model::block::consensus::ConsensusMode,
    parameters: iroha_data_model::block::consensus::SumeragiGenesisContextParameters,
    cadence_ms: u64,
}

/// Authenticate fixed signed inputs without executing or manufacturing an execution verdict.
fn validate_available_genesis_inputs(
    config: &Config,
    genesis: &GenesisBlock,
) -> ReportResult<GenesisStaticInputs, MainError> {
    let configured_key = &config.genesis.public_key;
    let embedded_key =
        genesis_public_key_from_genesis_block(&genesis.0).change_context(MainError::Config)?;
    if &embedded_key != configured_key {
        return Err(Report::new(MainError::Config).attach(format!(
            "genesis authority `{embedded_key}` does not match configured genesis.public_key `{configured_key}`"
        )));
    }
    if genesis.0.hash() != config.genesis.expected_hash {
        return Err(Report::new(MainError::Config).attach(format!(
            "local genesis hash {} does not match configured genesis.expected_hash {}",
            genesis.0.hash(),
            config.genesis.expected_hash,
        )));
    }
    let genesis_account = AccountId::new(embedded_key);
    iroha_core::validate_genesis_block(&genesis.0, &genesis_account)
        .map_err(Report::new)
        .change_context(MainError::Config)?;
    let (signed_mode, signed_parameters) = signed_genesis_context_metadata(&genesis.0)
        .map_err(|error| Report::new(MainError::Config).attach(error))?;
    let config_caps =
        build_consensus_config_caps(&config.nexus, None, None).change_context(MainError::Config)?;
    let (mode_tag, _bls_domain, consensus_caps, block_cadence_ms, _maximum_validator_roster_len) =
        consensus_caps_from_genesis(genesis, &config_caps).ok_or_else(|| {
            Report::new(MainError::Config).attach(
                "local genesis does not contain one valid canonical Sumeragi handshake context",
            )
        })?;
    verify_genesis_metadata(
        genesis,
        config,
        &consensus_caps,
        &mode_tag,
        iroha_core::sumeragi::consensus::PROTO_VERSION,
    )?;
    Ok(GenesisStaticInputs {
        authority: genesis_account,
        mode: signed_mode,
        parameters: signed_parameters,
        cadence_ms: block_cadence_ms,
    })
}

fn validate_available_genesis_for_check(
    config: &Config,
    genesis: &GenesisBlock,
    required_inrou_deployment_authority: Option<&AccountId>,
) -> ReportResult<(crate::authenticated_genesis::AuthenticatedGenesis, u64), MainError> {
    let GenesisStaticInputs {
        authority: genesis_account,
        mode: signed_mode,
        parameters: signed_parameters,
        cadence_ms: block_cadence_ms,
    } = validate_available_genesis_inputs(config, genesis)?;
    validate_genesis_execution_offline(
        config,
        genesis,
        &genesis_account,
        signed_mode,
        signed_parameters,
        block_cadence_ms,
        required_inrou_deployment_authority,
    )
    .map(|validated_genesis| (validated_genesis, block_cadence_ms))
}
struct DisposableValidationRoot {
    path: PathBuf,
}
impl DisposableValidationRoot {
    fn create() -> std::io::Result<Self> {
        let parent = env::temp_dir();
        for _ in 0..32 {
            let mut nonce = [0_u8; 16];
            rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut nonce)
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "operating-system randomness unavailable for temporary validation storage: {error}"
                    ))
                })?;
            let path = parent.join(format!(
                "irohad-check-config-{}-{}",
                std::process::id(),
                hex::encode(nonce)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate a unique temporary validation directory after 32 attempts",
        ))
    }
    fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for DisposableValidationRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            iroha_logger::warn!(
                path = %self.path.display(),
                ?error,
                "failed to remove disposable check-config storage"
            );
        }
    }
}
fn open_disposable_validation_kura(
    config: &Config,
    validation_root: &DisposableValidationRoot,
) -> ReportResult<Arc<Kura>, MainError> {
    let mut kura_config = config.kura.clone();
    kura_config.store_dir = WithOrigin::inline(validation_root.path().join("kura"));
    let (kura, block_count) = Kura::new_with_configured_lane_catalog(
        &kura_config,
        &config.nexus.lane_config,
        &config.nexus.configured_lane_catalog,
    )
    .map_err(|error| {
        Report::new(MainError::Config).attach(format!(
            "failed to initialize disposable Kura for genesis validation: {error}"
        ))
    })?;
    if block_count.0 != 0 {
        return Err(Report::new(MainError::Config).attach(format!(
            "disposable genesis validation storage was not empty ({} blocks)",
            block_count.0
        )));
    }
    Ok(kura)
}
/// Execute and publish the original signed genesis through native startup in a disposable State.
///
/// The same schedule, execution, and publication checks used by a fresh node run against
/// temporary Kura storage before the configured storage or listening sockets are opened.
fn validate_genesis_execution_offline(
    config: &Config,
    genesis: &GenesisBlock,
    genesis_authority: &AccountId,
    signed_mode: iroha_data_model::block::consensus::ConsensusMode,
    _signed_parameters: iroha_data_model::block::consensus::SumeragiGenesisContextParameters,
    expected_block_cadence_ms: u64,
    required_inrou_deployment_authority: Option<&AccountId>,
) -> ReportResult<crate::authenticated_genesis::AuthenticatedGenesis, MainError> {
    let validation_root = DisposableValidationRoot::create().map_err(|error| {
        Report::new(MainError::Config).attach(format!(
            "failed to create disposable storage for genesis validation: {error}"
        ))
    })?;
    let kura = open_disposable_validation_kura(config, &validation_root)?;
    let execution_budget =
        iroha_allocation::AllocationBudget::new(config.pipeline.ivm_execution_max_bytes);
    let mut world = World::try_with_execution_budget(
        [genesis_domain(config.genesis.public_key.clone())],
        [genesis_account(config.genesis.public_key.clone())],
        [],
        &execution_budget,
    )
    .map_err(|error: iroha_core::state::WorldConstructionError| {
        Report::new(error).change_context(MainError::Config)
    })?;
    iroha_core::sns::seed_genesis_alias_bootstrap(
        &mut world,
        &genesis.0,
        &config.nexus.dataspace_catalog,
    )
    .map_err(|error| Report::new(MainError::Config).attach(error))?;
    let mut state = State::try_new_with_chain_and_network_id(
        execution_budget,
        world,
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
        config.common.chain.clone(),
        NetworkId::from_genesis_hash(config.genesis.expected_hash),
        #[cfg(feature = "telemetry")]
        StateTelemetry::default(),
    )
    .map_err(|error| {
        Report::new(MainError::Config).attach(format!(
            "failed to initialize disposable world state for genesis validation: {error}"
        ))
    })?;
    install_zk_config_before_kura_replay(&mut state, config).change_context(MainError::Config)?;
    apply_state_runtime_config_before_snapshot_auth(&mut state, config)
        .map_err(|error| Report::new(error).change_context(MainError::Config))?;
    let baseline = freeze_lane_manifests_for_startup_replay(&config.nexus)
        .map_err(|error| Report::new(error).change_context(MainError::Config))?;
    let startup_policies =
        install_lane_policies_for_startup_replay(&mut state, config.nexus.clone(), &baseline)
            .change_context(MainError::Config)?;
    apply_state_geometry_config_before_kura_replay(&mut state, &startup_policies)
        .change_context(MainError::Config)?;
    iroha_core::sumeragi::startup::apply_genesis(
        &state,
        genesis.0.clone(),
        genesis_authority,
        signed_mode,
        None,
    )
    .map_err(|error| {
        Report::new(error)
            .change_context(MainError::Config)
            .attach("native genesis execution failed")
    })?;
    let executed = state.world_view();
    let initial_configs = executed
        .consensus_schedule()
        .init_configs(iroha_core::sumeragi::startup::GENESIS_HEIGHT)
        .map_err(|error| Report::new(MainError::Config).attach(error.to_string()))?;
    let initial_committee_size = initial_configs
        .iter()
        // Only an installed slot carries a committee; a pending boundary fails closed.
        .find_map(|(_, slot)| slot.ready().map(|config| config.committee.n()))
        .ok_or_else(|| {
            Report::new(MainError::Config)
                .attach("executed native genesis has no authenticated ready committee")
        })?;
    if required_inrou_deployment_authority.is_some_and(|authority| {
        !iroha_core::smartcontracts::isi::soracloud::soracloud_management_authority_is_authorized(
            &executed, authority,
        )
    }) {
        return Err(Report::new(MainError::Config).attach(
            "required Inrou deployment authority is absent or lacks exact CanManageSoracloud in final genesis state",
        ));
    }
    let staged_block_cadence_ms = executed.parameters().sumeragi().block_cadence_ms().get();
    if staged_block_cadence_ms != expected_block_cadence_ms {
        return Err(Report::new(MainError::Config).attach(format!(
            "staged genesis cadence {staged_block_cadence_ms} ms differs from authenticated signed cadence {expected_block_cadence_ms} ms"
        )));
    }
    let authenticated = iroha_data_model::sumeragi_finality::authenticated_genesis(&genesis.0)
        .map_err(|error| Report::new(MainError::Config).attach(error))?;
    let metadata = authenticated.metadata();
    let epoch = authenticated.into_parts().0;
    // The native genesis path checked the exact signed epoch and both policy commitments
    // against original execution before publishing this disposable State.
    let execution_policy_hash = Hash::prehashed(metadata.sumeragi_context.execution_policy_hash);
    let nexus_amx_context_hash = Hash::prehashed(metadata.sumeragi_context.nexus_amx_context_hash);
    Ok(crate::authenticated_genesis::AuthenticatedGenesis {
        network_id: epoch.network_id,
        initial_committee_size,
        execution_policy_hash,
        nexus_amx_context_hash,
    })
}
fn parse_confidential_registry_hash(payload: &Json) -> ReportResult<Option<[u8; 32]>, MainError> {
    let meta = decode_confidential_registry_meta(payload).map_err(|err| {
        Report::new(MainError::Config).attach(format!(
            "failed to decode confidential_registry_root payload: {err}"
        ))
    })?;
    if let Some(hash_str) = meta.vk_set_hash {
        let trimmed = hash_str.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("null") {
            return Ok(None);
        }
        let body = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if body.len() != 64 || !body.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err(Report::new(MainError::Config).attach(format!(
                "confidential_registry_root.vk_set_hash must be 32-byte hex, got `{hash_str}`"
            )));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(body, &mut bytes).map_err(|err| {
            Report::new(MainError::Config).attach(format!(
                "failed to decode confidential_registry_root.vk_set_hash `{hash_str}`: {err}"
            ))
        })?;
        Ok(Some(bytes))
    } else {
        Ok(None)
    }
}
fn build_consensus_config_caps(
    nexus: &iroha_config::parameters::actual::Nexus,
    compliance_policy_digest: Option<[u8; 32]>,
    lane_manifest_policy_digest: Option<[u8; 32]>,
) -> ReportResult<iroha_p2p::ConsensusConfigCaps, StartError> {
    let nexus_policy_digest =
        iroha_config::parameters::actual::nexus_consensus_policy_digest_with_runtime_policies(
            nexus,
            compliance_policy_digest,
            lane_manifest_policy_digest,
        )
        .map_err(|err| {
            Report::new(StartError::StartP2p).attach(format!(
                "failed to construct Nexus consensus-policy digest: {err}"
            ))
        })?;
    Ok(iroha_p2p::ConsensusConfigCaps {
        // The signed genesis/world projection replaces this bootstrap value
        // before the handshake is exposed to peers.
        native_config_fingerprint: [0; 32],
        execution_policy_hash: [0; 32],
        nexus_policy_digest,
        ivm_gas_schedule_hash: ivm::gas::schedule_hash().into(),
    })
}
fn consensus_caps_from_genesis(
    genesis: &GenesisBlock,
    config_caps: &iroha_p2p::ConsensusConfigCaps,
) -> Option<(
    String,
    String,
    iroha_p2p::ConsensusHandshakeCaps,
    u64,
    usize,
)> {
    let mut params = iroha_data_model::parameter::Parameters::default();
    let mut handshake_entries = Vec::new();
    for tx in genesis.0.external_transactions() {
        if let Executable::Instructions(batch) = tx.instructions() {
            for instr in batch {
                if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>() {
                    if let iroha_data_model::parameter::Parameter::Custom(custom) =
                        set_param.inner()
                        && custom.id() == &consensus_metadata::handshake_meta_id()
                        && let Ok(meta) = decode_consensus_handshake_meta(custom.payload())
                    {
                        handshake_entries.push(meta);
                    }
                    params.set_parameter(set_param.inner().clone());
                }
            }
        }
    }
    let [entry] = handshake_entries.as_slice() else {
        return None;
    };
    if entry.wire_protocol_version != u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION) {
        return None;
    }
    let (expected_mode, expected_domain) = match entry.mode {
        iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned => (
            iroha_data_model::block::consensus::ConsensusMode::Permissioned,
            iroha_data_model::block::consensus::PERMISSIONED_BLS_DOMAIN,
        ),
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos => (
            iroha_data_model::block::consensus::ConsensusMode::Npos,
            iroha_data_model::block::consensus::NPOS_BLS_DOMAIN,
        ),
    };
    params.sumeragi.block_cadence_ms = entry.block_cadence_ms;
    let (mode_tag, consensus_params, computed_fingerprint) =
        consensus_entry_caps(entry, &params).ok()?;
    if entry.consensus_fingerprint.into_bytes() != computed_fingerprint {
        return None;
    }
    let (permissioned_roster_len, npos_max_validators) = match &consensus_params.mode {
        iroha_data_model::block::consensus::ConsensusGenesisModeParams::Permissioned
            if expected_mode == iroha_data_model::block::consensus::ConsensusMode::Permissioned =>
        {
            (
                iroha_core::sumeragi::schedule::genesis_validators(genesis)
                    .ok()?
                    .len(),
                None,
            )
        }
        iroha_data_model::block::consensus::ConsensusGenesisModeParams::Npos(npos)
            if expected_mode == iroha_data_model::block::consensus::ConsensusMode::Npos =>
        {
            (0, Some(npos.max_validators))
        }
        _ => return None,
    };
    let maximum_validator_roster_len = authenticated_maximum_validator_roster_len(
        expected_mode,
        permissioned_roster_len,
        npos_max_validators,
    )
    .ok()?;
    let mut config_caps = *config_caps;
    config_caps.execution_policy_hash = entry.sumeragi_context.execution_policy_hash;
    config_caps.native_config_fingerprint =
        iroha_core::sumeragi::node::consensus_configuration_fingerprint(&genesis.0)
            .ok()?
            .into();
    Some((
        mode_tag.clone(),
        expected_domain.to_owned(),
        iroha_p2p::ConsensusHandshakeCaps {
            mode: expected_mode,
            proto_version: iroha_core::sumeragi::consensus::PROTO_VERSION,
            consensus_fingerprint: computed_fingerprint,
            config: config_caps,
        },
        consensus_params.block_cadence_ms.get(),
        maximum_validator_roster_len,
    ))
}

fn signed_genesis_context_metadata(
    genesis: &SignedBlock,
) -> core::result::Result<
    (
        iroha_data_model::block::consensus::ConsensusMode,
        iroha_data_model::block::consensus::SumeragiGenesisContextParameters,
    ),
    String,
> {
    let mut metadata_entries = Vec::new();
    for transaction in genesis.external_transactions() {
        let Executable::Instructions(instructions) = transaction.instructions() else {
            return Err(
                "Sumeragi genesis metadata must be carried by instruction batches".to_owned(),
            );
        };
        for set_parameter in instructions
            .iter()
            .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        {
            let Parameter::Custom(custom) = set_parameter.inner() else {
                continue;
            };
            if custom.id() == &consensus_metadata::handshake_meta_id() {
                metadata_entries.push(
                    decode_consensus_handshake_meta(custom.payload())
                        .map_err(|error| error.to_string())?,
                );
            }
        }
    }
    let [metadata] = metadata_entries.as_slice() else {
        return Err(format!(
            "Sumeragi genesis requires exactly one signed handshake metadata entry, found {}",
            metadata_entries.len()
        ));
    };
    let expected_protocol = u32::from(iroha_data_model::sumeragi::PROTOCOL_VERSION);
    if metadata.wire_protocol_version != expected_protocol {
        return Err(format!(
            "Sumeragi genesis requires wire_protocol_version = {expected_protocol}, got {}",
            metadata.wire_protocol_version
        ));
    }
    metadata.validate()?;
    let mode = match metadata.mode {
        iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned => {
            iroha_data_model::block::consensus::ConsensusMode::Permissioned
        }
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos => {
            iroha_data_model::block::consensus::ConsensusMode::Npos
        }
    };
    Ok((mode, metadata.sumeragi_context))
}
fn consensus_entry_caps(
    entry: &ConsensusHandshakeMeta,
    params: &iroha_data_model::parameter::Parameters,
) -> EyreResult<(
    String,
    iroha_data_model::block::consensus::ConsensusGenesisParams,
    [u8; 32],
)> {
    let (mode, mode_tag) = match entry.mode {
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos => (
            iroha_data_model::block::consensus::ConsensusMode::Npos,
            iroha_core::sumeragi::consensus::NPOS_TAG,
        ),
        iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned => (
            iroha_data_model::block::consensus::ConsensusMode::Permissioned,
            iroha_core::sumeragi::consensus::PERMISSIONED_TAG,
        ),
    };
    let mut params = params.clone();
    params.sumeragi.block_cadence_ms = entry.block_cadence_ms;
    let consensus_params =
        iroha_core::sumeragi::consensus::consensus_genesis_params_from_parameters(
            mode,
            &params,
            entry.sumeragi_context,
        )
        .map_err(|error| eyre::eyre!(error))?;
    let fingerprint = iroha_core::sumeragi::consensus::compute_consensus_parameters_fingerprint(
        &consensus_params,
    )
    .map_err(|error| eyre::eyre!(error))?;
    Ok((mode_tag.to_string(), consensus_params, fingerprint))
}
#[allow(clippy::too_many_lines)]
fn verify_genesis_metadata(
    genesis: &GenesisBlock,
    config: &Config,
    consensus_caps: &iroha_p2p::ConsensusHandshakeCaps,
    mode_tag: &str,
    proto_version: u32,
) -> ReportResult<(), MainError> {
    let mut instructions: Vec<InstructionBox> = Vec::new();
    for tx in genesis.0.external_transactions() {
        match tx.instructions() {
            Executable::Instructions(batch) => {
                instructions.extend(batch.iter().cloned());
            }
            Executable::ContractCall(_) => {
                return Err(Report::new(MainError::Config).attach(
                    "genesis transaction payload contains contract calls; expected instruction batches",
                ));
            }
            Executable::Ivm(_) => {
                return Err(Report::new(MainError::Config).attach(
                    "genesis transaction payload contains raw IVM bytecode; expected instruction batches",
                ));
            }
            Executable::IvmProved(_) => {
                return Err(Report::new(MainError::Config).attach(
                    "genesis transaction payload contains proved IVM bytecode; expected instruction batches",
                ));
            }
            Executable::Batch(_) => {
                return Err(Report::new(MainError::Config).attach(
                    "genesis transaction payload contains a mixed executable batch; expected instruction batches",
                ));
            }
        }
    }
    let mut handshake_entries = Vec::new();
    for set_param in instructions
        .iter()
        .filter_map(|instr| instr.as_any().downcast_ref::<SetParameter>())
    {
        if let Parameter::Custom(custom) = set_param.inner()
            && custom.id() == &consensus_metadata::handshake_meta_id()
        {
            let meta: ConsensusHandshakeMeta = decode_consensus_handshake_meta(custom.payload())
                .map_err(|err| {
                    Report::new(MainError::Config).attach(format!(
                        "failed to decode consensus_handshake_meta payload: {err}"
                    ))
                })?;
            handshake_entries.push(meta);
        }
    }
    if handshake_entries.is_empty() {
        return Err(Report::new(MainError::Config).attach(
            "genesis block missing consensus_handshake_meta parameter; regenerate genesis with consensus metadata populated",
        ));
    }
    let expected_mode = if mode_tag == iroha_core::sumeragi::consensus::PERMISSIONED_TAG {
        iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned
    } else if mode_tag == iroha_core::sumeragi::consensus::NPOS_TAG {
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos
    } else {
        return Err(Report::new(MainError::Config)
            .attach(format!("unknown consensus mode tag `{mode_tag}`")));
    };
    let expected_fp_hex = hex::encode(consensus_caps.consensus_fingerprint);
    let mut matched_meta: Option<ConsensusHandshakeMeta> = None;
    for meta in &handshake_entries {
        if meta.mode != expected_mode {
            continue;
        }
        if meta.wire_protocol_version != proto_version {
            continue;
        }
        if meta.consensus_fingerprint.into_bytes() == consensus_caps.consensus_fingerprint {
            matched_meta = Some(meta.clone());
            break;
        }
    }
    let Some(matched_meta) = matched_meta else {
        let entries_summary = handshake_entries
            .iter()
            .map(|meta| {
                format!(
                    "{{mode={:?}, block_cadence_ms={}, wire_protocol_version={}, fingerprint=0x{}}}",
                    meta.mode,
                    meta.block_cadence_ms,
                    meta.wire_protocol_version,
                    hex::encode(meta.consensus_fingerprint.into_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Report::new(MainError::Config).attach(format!(
            "none of the consensus_handshake_meta entries match the authenticated startup context (expected consensus_mode `{expected_mode:?}`, proto v{proto_version}, fingerprint 0x{expected_fp_hex}`); entries observed: {entries_summary}"
        )));
    };
    let mut params = iroha_data_model::parameter::Parameters::default();
    for set_param in instructions
        .iter()
        .filter_map(|instr| instr.as_any().downcast_ref::<SetParameter>())
    {
        params.set_parameter(set_param.inner().clone());
    }
    params.sumeragi.block_cadence_ms = matched_meta.block_cadence_ms;
    let crypto_manifest_payload = instructions
        .iter()
        .filter_map(|instr| instr.as_any().downcast_ref::<SetParameter>())
        .find_map(|set| {
            if let Parameter::Custom(custom) = set.inner()
                && custom.id() == &crypto_metadata::manifest_meta_id()
            {
                Some(custom.payload())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            Report::new(MainError::Config).attach(
                "genesis block missing crypto_manifest_meta parameter; regenerate genesis with crypto metadata populated",
            )
        })?;
    let manifest_crypto: ManifestCrypto = decode_crypto_manifest_meta(crypto_manifest_payload)
        .map_err(|err| {
            Report::new(MainError::Config).attach(format!(
                "failed to decode crypto_manifest_meta payload: {err}"
            ))
        })?;
    ensure_crypto_snapshot_matches_config(&manifest_crypto, config)
        .map_err(|err| Report::new(MainError::Config).attach(err))?;
    let mode = if mode_tag == iroha_core::sumeragi::consensus::NPOS_TAG {
        iroha_data_model::block::consensus::ConsensusMode::Npos
    } else {
        iroha_data_model::block::consensus::ConsensusMode::Permissioned
    };
    let consensus_params =
        iroha_core::sumeragi::consensus::consensus_genesis_params_from_parameters(
            mode,
            &params,
            matched_meta.sumeragi_context,
        )
        .map_err(|error| Report::new(MainError::Config).attach(error))?;
    let computed_fp = iroha_core::sumeragi::consensus::compute_consensus_parameters_fingerprint(
        &consensus_params,
    )
    .map_err(|error| Report::new(MainError::Config).attach(error))?;
    if computed_fp != matched_meta.consensus_fingerprint.into_bytes() {
        return Err(Report::new(MainError::Config).attach(format!(
            "consensus_handshake_meta fingerprint 0x{} does not match parameters encoded in genesis (computed 0x{})",
            hex::encode(matched_meta.consensus_fingerprint.into_bytes()),
            hex::encode(computed_fp)
        )));
    }
    let expected_vk_hash = compute_genesis_vk_set_hash(instructions.iter()).map_err(|err| {
        Report::new(MainError::Config).attach(format!(
            "failed to evaluate confidential registry instructions in genesis: {err}"
        ))
    })?;
    let registry_payload = instructions
        .iter()
        .filter_map(|instr| instr.as_any().downcast_ref::<SetParameter>())
        .find_map(|set| {
            if let Parameter::Custom(custom) = set.inner()
                && custom.id() == &confidential_metadata::registry_root_id()
            {
                Some(custom.payload())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            Report::new(MainError::Config).attach(
                "genesis block missing confidential_registry_root parameter; regenerate genesis with confidential metadata populated",
            )
        })?;
    let declared_vk_hash = parse_confidential_registry_hash(registry_payload)?;
    if declared_vk_hash != expected_vk_hash {
        let declared = declared_vk_hash.map_or_else(
            || "null".to_string(),
            |hash| format!("0x{}", hex::encode(hash)),
        );
        let expected = expected_vk_hash.map_or_else(
            || "null".to_string(),
            |hash| format!("0x{}", hex::encode(hash)),
        );
        return Err(Report::new(MainError::Config).attach(format!(
            "genesis confidential registry root mismatch: manifest {declared} vs expected {expected}"
        )));
    }
    let mut genesis_peers: BTreeMap<PeerId, RegisterPeerWithPop> = BTreeMap::new();
    for register in instructions
        .iter()
        .filter_map(|instr| instr.as_any().downcast_ref::<RegisterPeerWithPop>())
    {
        if genesis_peers
            .insert(register.peer.clone(), register.clone())
            .is_some()
        {
            return Err(Report::new(MainError::Config).attach(format!(
                "genesis registers peer {} multiple times",
                register.peer
            )));
        }
    }
    let trusted = config.common.trusted_peers.value();
    let expected_validators = filter_validators_from_trusted(trusted);
    if expected_validators.is_empty() {
        if !genesis_peers.is_empty() {
            return Err(Report::new(MainError::Config).attach(format!(
                "genesis encodes {} validator(s) with PoP but configuration filters them all out",
                genesis_peers.len()
            )));
        }
        return Ok(());
    }
    for peer_id in expected_validators {
        let entry = genesis_peers
            .remove(&peer_id)
            .or_else(|| {
                trusted
                    .pops
                    .get(peer_id.public_key())
                    .map(|pop| RegisterPeerWithPop::new(peer_id.clone(), pop.clone()))
            })
            .ok_or_else(|| {
                Report::new(MainError::Config).attach(format!(
                    "genesis lacks RegisterPeerWithPop for validator {peer_id}"
                ))
            })?;
        let bls_pk = peer_id.public_key();
        match bls_pk.try_algorithm() {
            Ok(Algorithm::BlsNormal) => {}
            Ok(_) => {
                return Err(Report::new(MainError::Config)
                    .attach(format!("trusted peer {peer_id} must use a BLS-normal key")));
            }
            Err(err) => {
                return Err(Report::new(MainError::Config).attach(format!(
                    "trusted peer {peer_id} has malformed public key: {err}"
                )));
            }
        }
        if let Some(expected_pop) = trusted.pops.get(bls_pk) {
            if &entry.pop != expected_pop {
                return Err(Report::new(MainError::Config).attach(format!(
                    "genesis PoP for peer {peer_id} does not match configuration"
                )));
            }
        } else if !trusted.pops.is_empty() {
            return Err(Report::new(MainError::Config).attach(format!(
                "trusted peer {peer_id} missing PoP in configuration"
            )));
        }
        if let Err(err) = iroha_crypto::bls_normal_pop_verify(bls_pk, &entry.pop) {
            return Err(Report::new(MainError::Config).attach(format!(
                "genesis PoP for peer {peer_id} failed verification: {err}"
            )));
        }
    }
    if !genesis_peers.is_empty() {
        let extras = genesis_peers
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(Report::new(MainError::Config).attach(format!(
            "genesis encodes unexpected validators with PoP: {extras}"
        )));
    }
    Ok(())
}
async fn run_node(
    build: CompiledBuildMetadata,
    prepared: PreparedStartup,
    logger: LoggerHandle,
    runtime_deps: IrohaRuntimeDeps,
    musubi_publication_factory: Option<
        Box<dyn musubi_publication_service::MusubiPublicationPrivateServiceFactoryV1>,
    >,
) -> ReportResult<(), MainError> {
    let setup = (|| -> ReportResult<_, MainError> {
        let config = prepared.config();
        validate_startup_config(&config).change_context(MainError::Config)?;
        set_banner_enabled(config.ivm.banner.show);
        // Print a retro Norito banner with applied settings when enabled.
        if config.ivm.banner.show {
            log_norito_banner(&config);
        }
        iroha_logger::info!(
            version = build.version(),
            git_commit_sha = build.source_commit_label(),
            build_features = build.cargo_features_label(),
            peer = %config.common.peer,
            chain = %config.common.chain,
            listening_on = %config.torii.address.value(),
            "{}",
            i18n::t("info.welcome"),
        );
        if prepared.native.genesis.is_some() {
            iroha_logger::debug!("Prepared original signed genesis.");
        }
        #[cfg(feature = "beep")]
        startup_beep(config.ivm.banner.beep);
        let shutdown_on_panic = ShutdownSignal::new();
        let default_hook = std::panic::take_hook();
        let signal_clone = shutdown_on_panic.clone();
        std::panic::set_hook(Box::new(move |info| {
            let suppressed_by_panic_hook = iroha_panic_hook::is_suppressed();
            let suppressed_by_norito_decode = norito::decode_panic_suppressed();
            if suppressed_by_panic_hook || suppressed_by_norito_decode {
                let panic_file = info.location().map(std::panic::Location::file);
                let panic_line = info.location().map(std::panic::Location::line);
                iroha_logger::warn!(
                    suppressed_by_panic_hook,
                    suppressed_by_norito_decode,
                    ?panic_file,
                    ?panic_line,
                    "Panic occurred with shutdown suppression active; skipping shutdown signal"
                );
            } else {
                iroha_logger::error!("Panic occurred, shutting down Iroha gracefully...");
                signal_clone.send();
            }
            default_hook(info);
        }));
        Ok((
            logger,
            shutdown_on_panic,
            config.lifecycle.exit_on_stdin_close,
        ))
    })();
    let (logger, shutdown_on_panic, exit_on_stdin_close) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            return match prepared.close().await {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    Err(error.attach(format!("prepared startup cleanup failed: {cleanup:?}")))
                }
            };
        }
    };
    let start = Iroha::activate_with_runtime_deps(
        build,
        prepared,
        logger,
        shutdown_on_panic.clone(),
        runtime_deps,
        musubi_publication_factory,
    );
    let (_iroha, supervisor_fut) = Box::pin(start)
        .await
        .change_context(MainError::IrohaStart)?;
    // Never leave a detached stdin watcher after a provider or startup-admission failure.
    // Successful runtime ownership retains the established EOF lifetime contract.
    if exit_on_stdin_close {
        if let Err(error) = spawn_input_close_shutdown(std::io::stdin(), shutdown_on_panic.clone())
        {
            shutdown_on_panic.send();
            let error = Report::new(MainError::IrohaStart).attach(format!(
                "failed to watch standard input for lifecycle.exit_on_stdin_close: {error}"
            ));
            return match supervisor_fut.await {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    Err(error.attach(format!("startup activation cleanup failed: {cleanup:?}")))
                }
            };
        }
    }
    supervisor_fut.await.change_context(MainError::IrohaRun)
}
/// Shut the daemon down once `input` reaches end-of-file (`lifecycle.exit_on_stdin_close`).
///
/// A supervising parent holds the write end of the child's stdin pipe. When the parent exits for
/// any reason, including SIGKILL, the pipe closes and the node shuts down cleanly through the same
/// signal a panic uses. Bytes written to the pipe are discarded; a read error also shuts down.
fn spawn_input_close_shutdown(
    input: impl std::io::Read + Send + 'static,
    signal: ShutdownSignal,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("stdin-close-shutdown".to_owned())
        .spawn(move || {
            drain_until_eof(input);
            iroha_logger::info!("standard input closed, shutting down...");
            signal.send();
        })
        .map(drop)
}
/// Read and discard `input` until end-of-file or a read error.
fn drain_until_eof(mut input: impl std::io::Read) {
    let mut buffer = [0_u8; 256];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}
#[cfg(all(test, feature = "daemon", unix))]
#[path = "main/node_file_tests.rs"]
mod node_file_tests;
/// Print a startup banner with applied Norito codec settings in a retro style.
fn log_norito_banner(cfg: &Config) {
    // Snapshot core settings
    let n = &cfg.norito;
    let gpu_allowed = cfg.kura.init_mode != InitMode::Fast && n.allow_gpu_compression;
    let gpu_probe_status = if gpu_allowed { "deferred" } else { "disabled" };
    // UTF‑8 box drawing and kana render nicely in modern terminals.
    let art = r"
╔══════════════════════════════════════════════════════════════════════╗
║  ⛩  ノ  リ  ト   N O R I T O   ⛩     「速く、正しく、そして同じ結果」║
╠══════════════════════════════════════════════════════════════════════╣
║              ┌────────────── イロハ ──────────────┐                  ║
║              │      ────┬──────────────┬────      │                  ║
║              │          │  ノ  リ  ト  │          │                  ║
║              │      ────┴──────────────┴────      │                  ║
║              └────────────────────────────────────┘                  ║
╚══════════════════════════════════════════════════════════════════════╝
";
    // Compose settings block
    let msg = format!(
        "\n{}\nNorito settings:\n  - max_archive_len: {}\n  - gpu_offload_allowed: {}\n  - gpu_backend_probe: {}\n",
        art,
        resolve_norito_max_archive_len(cfg),
        gpu_allowed,
        gpu_probe_status,
    );
    iroha_logger::info!(target: "norito", "{}", msg);
}
#[cfg(test)]
mod tests {
    use super::config_tests::{
        load_unprovisioned_profile_for_inspection, minimal_config_table, multilane_config_table,
    };
    #[allow(unused_imports)]
    use super::*;
    use iroha_config_base::toml::TomlSource;
    use iroha_model_base::topology::LaneId;
    const GOVERNANCE_DAG_PUBLISHER_HANDLE: &str = "provider:governance-dag-publisher";
    const GOVERNANCE_DAG_PUBLISHER_PEER_ID: &str = "governance-dag-publisher";
    const GOVERNANCE_DAG_PUBLISHER_POLICY_DIGEST: [u8; 32] = [0xA5; 32];
    const GOVERNANCE_DAG_CHECKPOINT_STORE_HANDLE: &str =
        "sealed:governance-dag:producer-checkpoint";
    const GOVERNANCE_DAG_CHECKPOINT_STORE_POLICY_DIGEST: [u8; 32] = [0xA6; 32];
    #[cfg(feature = "telemetry")]
    #[tokio::test]
    async fn optional_telemetry_exit_does_not_stop_supervisor() {
        let mut supervisor = Supervisor::new();
        let shutdown = supervisor.shutdown_signal();
        monitor_optional_telemetry_task(&mut supervisor, "test", tokio::spawn(async {}));
        let run = tokio::spawn(supervisor.start());
        tokio::task::yield_now().await;
        assert!(
            !run.is_finished(),
            "optional telemetry completion must wait for node shutdown"
        );
        shutdown.send();
        tokio::time::timeout(std::time::Duration::from_secs(1), run)
            .await
            .expect("supervisor shutdown timeout")
            .expect("supervisor task")
            .expect("supervisor result");
    }
    #[cfg(feature = "telemetry")]
    #[tokio::test]
    async fn dropping_supervisor_aborts_optional_telemetry() {
        struct NotifyOnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for NotifyOnDrop {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let mut supervisor = Supervisor::new();
        let (dropped_sender, dropped_receiver) = tokio::sync::oneshot::channel();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _notify_on_drop = NotifyOnDrop(Some(dropped_sender));
            let _ = started_sender.send(());
            std::future::pending::<()>().await;
        });
        monitor_optional_telemetry_task(&mut supervisor, "test", handle);
        started_receiver.await.expect("optional telemetry start");
        drop(supervisor);
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_receiver)
            .await
            .expect("optional telemetry abort timeout")
            .expect("optional telemetry drop notification");
    }
    #[derive(Debug)]
    struct GovernanceDagPublisherBindingSigner {
        key_pair: iroha_crypto::KeyPair,
    }
    impl GovernanceDagPublisherBindingSigner {
        fn from_seed(seed: u8) -> Self {
            Self {
                key_pair: iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .expect("derive Governance DAG publisher key"),
            }
        }
        fn public_key_bytes(&self) -> [u8; 32] {
            self.key_pair
                .public_key()
                .to_bytes()
                .1
                .try_into()
                .expect("Ed25519 public key has 32 bytes")
        }
    }
    include!("main_tests/governance_dag_publisher_binding_signer.rs");
    #[derive(Debug)]
    struct GovernanceDagCheckpointBindingStore;
    impl sorafs_node::GovernanceDagSealedCheckpointStore for GovernanceDagCheckpointBindingStore {
        fn handle(&self) -> &str {
            GOVERNANCE_DAG_CHECKPOINT_STORE_HANDLE
        }
        fn qualification(
            &self,
        ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
            Ok(
                sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                    1,
                    GOVERNANCE_DAG_CHECKPOINT_STORE_POLICY_DIGEST,
                ),
            )
        }
        fn load(
            &self,
            _slot: sorafs_node::GovernanceDagSealedStateSlot,
        ) -> Result<Option<sorafs_node::GovernanceDagSealedStateRecord>, String> {
            Ok(None)
        }
        fn compare_and_swap(
            &self,
            _slot: sorafs_node::GovernanceDagSealedStateSlot,
            _expected_revision: Option<[u8; 32]>,
            _next: sorafs_node::GovernanceDagSealedStateRecord,
        ) -> Result<(), String> {
            Ok(())
        }
        fn delete(
            &self,
            _slot: sorafs_node::GovernanceDagSealedStateSlot,
            _expected_revision: [u8; 32],
        ) -> Result<(), String> {
            Ok(())
        }
    }
    fn governance_dag_publisher_public_key(seed: u8) -> [u8; 32] {
        GovernanceDagPublisherBindingSigner::from_seed(seed).public_key_bytes()
    }
    fn governance_dag_service_storage(
        public_key: [u8; 32],
    ) -> iroha_config::parameters::actual::SorafsStorage {
        let mut storage = iroha_config::parameters::actual::SorafsStorage {
            enabled: true,
            governance_dag_dir: Some(std::path::PathBuf::from("/var/lib/iroha/sorafs/governance")),
            governance_dag_publisher_peer_id: Some(GOVERNANCE_DAG_PUBLISHER_PEER_ID.to_owned()),
            governance_dag_signer_handle: Some(GOVERNANCE_DAG_PUBLISHER_HANDLE.to_owned()),
            governance_dag_signer_revision: Some(1),
            governance_dag_signer_policy_digest: Some(GOVERNANCE_DAG_PUBLISHER_POLICY_DIGEST),
            governance_dag_publisher_public_key_hex: Some(hex::encode(public_key)),
            ..Default::default()
        };
        storage.governance_dag_service.enabled = true;
        storage.governance_dag_service.checkpoint_store_handle =
            Some(GOVERNANCE_DAG_CHECKPOINT_STORE_HANDLE.to_owned());
        storage.governance_dag_service.checkpoint_store_revision = Some(1);
        storage
            .governance_dag_service
            .checkpoint_store_policy_digest = Some(GOVERNANCE_DAG_CHECKPOINT_STORE_POLICY_DIGEST);
        storage.governance_dag_service.publisher_public_key_hex = Some(hex::encode(public_key));
        storage
    }
    #[test]
    fn standard_launcher_does_not_derive_six_sorafs_authority_signers_from_node_key() {
        let dependencies = IrohaRuntimeDeps::default();
        assert!(dependencies.sorafs_stream_token_signer_client.is_none());
        assert!(dependencies.sorafs_stream_token_state_observer.is_none());
        assert!(dependencies.sorafs_stream_token_approved_anchor.is_none());
        assert!(dependencies.sorafs_proof_outcome_signer.is_none());
        assert!(dependencies.sorafs_repair_transaction_signer.is_none());
        assert!(dependencies.sorafs_reserve_transaction_signer.is_none());
        assert!(dependencies.sorafs_orderbook_transaction_signer.is_none());
        assert!(dependencies.sorafs_moderation_transaction_signer.is_none());
        assert!(dependencies.sorafs_moderation_settlement_handoff.is_none());
        assert!(dependencies.sorafs_moderation_publication_handoff.is_none());
        assert!(dependencies.sorafs_moderation_panel_notification.is_none());
        assert!(
            dependencies
                .sorafs_governance_dag_ipfs_authenticator
                .is_none()
        );
        assert!(
            dependencies
                .sorafs_governance_dag_head_authenticator
                .is_none()
        );
        assert!(
            dependencies
                .sorafs_governance_dag_checkpoint_store
                .is_none()
        );
        assert!(
            dependencies
                .sorafs_appeal_finance_checkpoint_runtime
                .is_none()
        );
        assert!(dependencies.sorafs_evidence_viewer_webauthn.is_none());
        assert!(dependencies.sorafs_evidence_viewer_grants.is_none());
        assert!(dependencies.sorafs_evidence_viewer_receipt_signer.is_none());
        assert!(dependencies.sorafs_evidence_viewer_erasure.is_none());
        assert!(
            dependencies
                .sorafs_evidence_viewer_checkpoint_store
                .is_none()
        );
        assert!(
            dependencies
                .sorafs_evidence_viewer_compaction_archive
                .is_none()
        );
        assert!(
            dependencies
                .sorafs_moderation_panel_notification_archive
                .is_none()
        );
        assert!(
            dependencies
                .sorafs_pop_credential_provider_registry
                .is_none()
        );
        assert!(
            dependencies
                .sorafs_provider_ingest_checkpoint_runtime
                .is_none()
        );
        assert!(
            dependencies
                .sorafs_provider_ingest_retention_authority
                .is_none()
        );
        assert!(dependencies.sorafs_reputation_retention_authority.is_none());
    }
    #[test]
    fn governance_dag_service_accepts_exact_embedded_publisher_binding() {
        let signer = Arc::new(GovernanceDagPublisherBindingSigner::from_seed(0x51));
        let public_key = signer.public_key_bytes();
        let storage = governance_dag_service_storage(public_key);
        let runtime_deps = IrohaRuntimeDeps::default().with_sorafs_governance_dag_signer(signer);
        validate_governance_dag_service_publisher_binding(
            &storage,
            runtime_deps.sorafs_governance_dag_signer.as_deref(),
        )
        .expect("service, producer configuration, and runtime signer must cross-bind");
        assert_eq!(
            storage.governance_dag_signer_handle.as_deref(),
            Some(GOVERNANCE_DAG_PUBLISHER_HANDLE)
        );
        assert_eq!(storage.governance_dag_signer_revision, Some(1));
        assert_eq!(
            storage.governance_dag_signer_policy_digest,
            Some(GOVERNANCE_DAG_PUBLISHER_POLICY_DIGEST)
        );
        assert_eq!(
            storage.governance_dag_publisher_peer_id.as_deref(),
            Some(GOVERNANCE_DAG_PUBLISHER_PEER_ID)
        );
        assert!(storage.governance_dag_dir.is_some());
    }
    #[test]
    fn disabled_governance_dag_service_leaves_shared_checkpoint_store_for_local_producer() {
        let signer = Arc::new(GovernanceDagPublisherBindingSigner::from_seed(0x57));
        let mut storage = governance_dag_service_storage(signer.public_key_bytes());
        storage.governance_dag_service.enabled = false;
        storage.governance_dag_service.publisher_public_key_hex = None;
        let runtime_deps = IrohaRuntimeDeps::default()
            .with_sorafs_governance_dag_signer(signer)
            .with_sorafs_governance_dag_checkpoint_store(Arc::new(
                GovernanceDagCheckpointBindingStore,
            ));
        let launch = resolve_governance_dag_service_launch(&storage, &runtime_deps)
            .expect("disabled public service must leave producer-owned roles available");
        assert!(
            launch.is_none(),
            "disabled public service must not start a supervised service"
        );
        assert!(
            runtime_deps
                .sorafs_governance_dag_checkpoint_store
                .is_some(),
            "the same resolved checkpoint store remains available for NodeRuntimeDeps"
        );
    }
    #[test]
    fn governance_dag_publisher_binding_signer_produces_valid_ed25519_signatures() {
        let signer = GovernanceDagPublisherBindingSigner::from_seed(0x50);
        let payload =
            sorafs_node::governance_dag_key_transition_signing_payload_v1(1, 2, [0x50; 32])
                .expect("governance key-transition payload");
        let purpose = sorafs_node::GovernanceDagSigningPurposeV1::KeyTransition;
        let signature = sorafs_node::GovernanceDagRuntimeSigner::sign(&signer, purpose, &payload)
            .expect("sign payload");
        let repeated = sorafs_node::GovernanceDagRuntimeSigner::sign(&signer, purpose, &payload)
            .expect("repeat signing");
        assert_eq!(signature, repeated);
        assert_eq!(
            sorafs_node::GovernanceDagRuntimeSigner::handle(&signer),
            GOVERNANCE_DAG_PUBLISHER_HANDLE
        );
        iroha_crypto::Signature::from_bytes(&signature)
            .verify(signer.key_pair.public_key(), &payload)
            .expect("deterministic Governance DAG signature must verify");
    }
    #[test]
    fn governance_dag_service_rejects_substituted_publisher_configuration() {
        let signer = GovernanceDagPublisherBindingSigner::from_seed(0x52);
        let producer_public_key = signer.public_key_bytes();
        let mut storage = governance_dag_service_storage(producer_public_key);
        storage.governance_dag_service.publisher_public_key_hex =
            Some(hex::encode(governance_dag_publisher_public_key(0x53)));
        let error = validate_governance_dag_service_publisher_binding(&storage, Some(&signer))
            .expect_err("substituted service publisher key must fail before state access");
        assert!(
            error
                .to_string()
                .contains("does not match the embedded producer configuration")
        );
    }
    #[test]
    fn governance_dag_service_rejects_missing_or_substituted_runtime_signer() {
        let public_key = governance_dag_publisher_public_key(0x54);
        let storage = governance_dag_service_storage(public_key);
        let missing = resolve_governance_dag_service_launch(&storage, &IrohaRuntimeDeps::default())
            .expect_err("missing embedded producer signer must fail before state access");
        assert!(
            missing
                .to_string()
                .contains("requires the embedded producer runtime signer")
        );
        let substituted = GovernanceDagPublisherBindingSigner::from_seed(0x55);
        let error = validate_governance_dag_service_publisher_binding(&storage, Some(&substituted))
            .expect_err("substituted runtime signer must fail before state access");
        assert!(
            error
                .to_string()
                .contains("does not match the embedded producer runtime signer")
        );
    }
    #[test]
    fn governance_dag_service_rejects_missing_embedded_producer_configuration() {
        let signer = GovernanceDagPublisherBindingSigner::from_seed(0x56);
        let public_key = signer.public_key_bytes();
        let mut storage = governance_dag_service_storage(public_key);
        storage.governance_dag_publisher_public_key_hex = None;
        let error = validate_governance_dag_service_publisher_binding(&storage, Some(&signer))
            .expect_err("missing embedded producer binding must fail before state access");
        assert!(
            error
                .to_string()
                .contains("requires the embedded producer public-key binding")
        );
    }
    #[test]
    fn repository_iroha3_dev_default_config_requests_no_runtime_providers() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../defaults/kagami/iroha3-dev/peer0.toml");
        let config = load_unprovisioned_profile_for_inspection(&path);
        let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project default provider bindings");
        assert!(
            bindings.is_empty(),
            "stock newcomer defaults must not require a deployment registry"
        );
    }
    #[test]
    fn reputation_runtime_provider_presence_fails_closed_in_both_modes() {
        assert!(validate_reputation_runtime_provider_presence(false, [false; 4]).is_ok());
        for provider_presence in [
            [true, false, false, false],
            [false, true, false, false],
            [false, false, true, false],
            [false, false, false, true],
        ] {
            assert_eq!(
                validate_reputation_runtime_provider_presence(false, provider_presence),
                Err("disabled SoraFS reputation runtime rejects unexpected runtime providers")
            );
        }
        assert!(
            validate_reputation_runtime_provider_presence(true, [true; 4]).is_ok(),
            "enabled reputation runtime passes presence validation before exact qualification"
        );
        for (provider_presence, expected_error) in [
            (
                [false, true, true, true],
                "enabled SoraFS reputation runtime requires an injected monotonic journal-checkpoint provider",
            ),
            (
                [true, false, true, true],
                "enabled SoraFS reputation runtime requires an injected authenticated journal-transaction submitter",
            ),
            (
                [true, true, false, true],
                "enabled SoraFS reputation runtime requires an injected external threshold signer",
            ),
            (
                [true, true, true, false],
                "enabled SoraFS reputation runtime requires an injected authenticated Governance DAG adapter",
            ),
        ] {
            assert_eq!(
                validate_reputation_runtime_provider_presence(true, provider_presence),
                Err(expected_error)
            );
        }
    }
    #[test]
    fn reputation_archive_presence_matches_runtime_enablement() {
        assert!(validate_reputation_archive_presence(false, false).is_ok());
        assert!(validate_reputation_archive_presence(true, true).is_ok());
        assert_eq!(
            validate_reputation_archive_presence(true, false),
            Err(
                "enabled SoraFS reputation runtime requires its daemon-owned archive before Sumeragi startup"
            )
        );
        assert_eq!(
            validate_reputation_archive_presence(false, true),
            Err("disabled SoraFS reputation runtime rejects an unexpected Sumeragi archive")
        );
    }
    #[test]
    fn provider_ingest_archive_presence_matches_runtime_enablement() {
        assert!(validate_provider_ingest_archive_presence(false, false).is_ok());
        assert!(validate_provider_ingest_archive_presence(true, true).is_ok());
        assert_eq!(
            validate_provider_ingest_archive_presence(true, false),
            Err(
                "enabled SoraFS provider-ingest runtime requires its daemon-owned archive before Sumeragi startup"
            )
        );
        assert_eq!(
            validate_provider_ingest_archive_presence(false, true),
            Err("disabled SoraFS provider-ingest runtime rejects an unexpected finalized archive")
        );
    }
    #[test]
    fn provider_attestation_journal_requires_concrete_native_selection() {
        assert!(validate_provider_attestation_journal_activation(false, false).is_ok());
        assert!(validate_provider_attestation_journal_activation(true, true).is_ok());
        assert_eq!(
            validate_provider_attestation_journal_activation(true, false),
            Err("provider-attestation activation requires the concrete native custody owner")
        );
        let startup = include_str!("main.rs")
            .split_once("pub(crate) async fn start_with_runtime_deps")
            .expect("runtime-dependency startup entry")
            .1;
        let activation_gate = startup
            .find("validate_provider_attestation_journal_activation")
            .expect("provider-attestation activation gate");
        let writer = startup
            .find("Kura::start(kura.clone(), supervisor.shutdown_signal())")
            .expect("Kura writer activation");
        assert!(
            activation_gate < writer,
            "an unqualified capture request must fail before persistent runtime activation"
        );
    }
    #[test]
    fn provider_ingest_archive_is_qualified_and_installed_before_runtime_startup() {
        let source = include_str!("main.rs");
        let adapter_preflight = source
            .find("let sorafs_provider_ingest_preflight = if emergency_fast")
            .expect("provider-ingest state-free adapter preflight");
        let preparation = source
            .find("prepare_provider_ingest_finalized_archive_v1")
            .expect("provider-ingest archive preparation");
        let sumeragi_start = source
            .find("let sumeragi = match prepared_sumeragi")
            .expect("Sumeragi startup");
        assert!(
            adapter_preflight < preparation && preparation < sumeragi_start,
            "external adapter preflight and archive qualification must fail closed before consensus starts"
        );
        let node_state_open = source
            .find("sorafs_node::NodeHandle::try_new_with_policies_and_runtime_deps")
            .expect("embedded SoraFS durable-state startup");
        let checkpoint_injection = source
            .find("with_provider_ingest_checkpoint_runtime")
            .expect("provider-ingest checkpoint injection");
        assert!(
            adapter_preflight < checkpoint_injection && checkpoint_injection < node_state_open,
            "provider-ingest external adapters must be qualified before the checkpoint provider can reach NodeHandle or initialize the outbox"
        );
        let provider_runtime_start = source
            .find("let sorafs_provider_ingest_runtime = if let Some")
            .expect("provider-ingest runtime startup");
        assert!(
            sumeragi_start < provider_runtime_start,
            "the commit-capturing archive must be installed before its runtime reader starts"
        );
        let archive_binding = source
            .find(".attach_finalized_archives(")
            .expect("synchronous current executor archive binding");
        let consensus_driver_start = source[archive_binding..]
            .find(".start_on_network(")
            .map(|offset| archive_binding + offset)
            .expect("current consensus driver startup");
        assert!(
            preparation < archive_binding
                && archive_binding < consensus_driver_start
                && consensus_driver_start < provider_runtime_start,
            "the reconciled archive must bind to current commit capture before consensus or its reader starts"
        );
        let runtime_wiring = &source[provider_runtime_start..];
        assert!(
            runtime_wiring.contains("sorafs_provider_ingest_finalized_query"),
            "provider ingest must consume the archive-only finalized query"
        );
        assert!(
            runtime_wiring.contains("sorafs_provider_ingest_preflight"),
            "provider ingest must consume the opaque state-free preflight token"
        );
    }
    #[test]
    fn emergency_fast_does_not_construct_the_daemon_sorafs_node() {
        let compact_source: String = include_str!("main.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let startup_source = compact_source
            .split_once("pub(crate)asyncfnstart_with_runtime_deps(")
            .expect("start_with_runtime_deps source")
            .1
            .split_once("///Read-onlyhandletotheworldstateview.")
            .expect("start_with_runtime_deps source boundary")
            .0;
        let fast_branch = startup_source
            .find("letmutsorafs_node=ifemergency_fast{None}else{Some(")
            .expect("emergency Fast SoraFS omission");
        let durable_constructor = startup_source
            .find("sorafs_node::NodeHandle::try_new_with_policies_and_runtime_deps(")
            .expect("Strict SoraFS constructor");
        let guarded_injection = startup_source
            .find("letruntime_deps=ifletSome(sorafs_node)=sorafs_node{")
            .expect("conditional Torii SoraFS injection");

        assert!(fast_branch < durable_constructor && durable_constructor < guarded_injection);
    }
    #[test]
    fn emergency_fast_skips_tiered_state_directory_reconciliation() {
        let preparation = include_str!("startup_preparation.rs");
        let tiered_setup = preparation
            .split_once("// Thread the remaining runtime preferences from config")
            .expect("tiered-state runtime setup")
            .1;
        let fast_guard = tiered_setup
            .find("if emergency_fast")
            .expect("emergency Fast tiered-state guard");
        let reconciliation = tiered_setup
            .find(".set_tiered_backend(&config.tiered_state)")
            .expect("Strict tiered-state reconciliation");
        let pipeline_runtime = tiered_setup
            .find("install_node_pipeline_config(&mut state, &config)")
            .expect("Strict pipeline runtime setup");
        assert!(
            fast_guard < reconciliation && reconciliation < pipeline_runtime,
            "emergency Fast must branch before tiered storage or the pipeline worker pool can be initialized"
        );
        // Both Strict steps are in the `else` of that one guard.
        let strict_branch = &tiered_setup[fast_guard..pipeline_runtime];
        assert_eq!(strict_branch.matches(concat!("} ", "else {")).count(), 1);
        assert_eq!(
            strict_branch
                .matches(concat!("if ", "emergency_fast"))
                .count(),
            1
        );
        // The pipeline is installed as node-local resources only: startup holds
        // no installation of a complete pipeline settings value.
        assert!(!tiered_setup[..pipeline_runtime].contains(concat!(".set_", "pipeline(")));
    }
    #[test]
    fn startup_handshake_digest_scans_no_confidential_registry() {
        // Neither emergency Fast nor Strict startup scans the confidential registry or
        // reads State for the handshake digest: it identifies the release.
        let source = include_str!("main.rs");
        let startup = source
            .split_once("pub(crate) async fn start_with_runtime_deps")
            .expect("runtime-dependency startup entry")
            .1;
        let confidential_setup = startup
            .split_once("let confidential_features = handshake_confidential_features();")
            .expect("release-bound confidential handshake digest")
            .1
            .split_once("let confidential_caps = iroha_p2p::ConfidentialHandshakeCaps {")
            .expect("confidential handshake caps")
            .0;
        assert!(!confidential_setup.contains("state.zk_snapshot()"));
        assert!(!confidential_setup.contains("let view = state.view()"));
        assert!(!confidential_setup.contains("compute_confidential_feature_digest("));
        let digest = source
            .split_once("fn handshake_confidential_features()")
            .expect("handshake digest function")
            .1
            .split_once("fn confidential_handshake_policy_digest(")
            .expect("end of the handshake digest function")
            .0;
        assert!(digest.contains("default_genesis_confidential_policy_hash()"));
        assert!(!digest.contains("state."));
        assert!(!digest.contains("config."));
    }
    #[test]
    fn emergency_fast_skips_strict_restart_audits_and_pipeline_diagnostics() {
        let startup = include_str!("main.rs")
            .split_once("pub(crate) async fn start_with_runtime_deps")
            .expect("runtime-dependency startup entry")
            .1;

        // Fast neither rebuilds the state through Sumeragi nor validates a genesis manifest.
        assert!(
            include_str!("startup_preparation.rs")
                .contains("let prepared_sumeragi = if emergency_fast {\n            None")
        );
        assert!(startup.contains("if !emergency_fast && let Some(json_path) = cfg_manifest"));

        let diagnostics = startup
            .split_once("// Recovery: scan recent persisted pipeline sidecars")
            .expect("pipeline recovery diagnostics")
            .1
            .split_once(
                "if let Some((queue_task, telemetry_task, governance_task, registry_cfg_task)) =",
            )
            .expect("end of pipeline recovery diagnostics")
            .0;
        assert_eq!(
            diagnostics.matches("if !emergency_fast {").count(),
            2,
            "both feature variants must skip pipeline sidecars in emergency Fast mode"
        );
    }
    #[test]
    fn emergency_fast_keeps_query_telemetry_and_time_workers_inert() {
        let implementation = include_str!("main.rs")
            .split_once("fn emergency_fast_keeps_query_telemetry_and_time_workers_inert")
            .expect("emergency Fast source assertion boundary")
            .0;
        let compact_source: String = include_str!("startup_preparation.rs")
            .chars()
            .chain(implementation.chars())
            .filter(|character| !character.is_whitespace())
            .collect();

        assert!(compact_source.contains(
            "letlive_query_store=ifemergency_fast{live_query_store.into_inert_handle()}else{let(handle,child)=live_query_store.start();supervisor.monitor(child);handle};"
        ));
        assert!(compact_source.contains(
            "lettelemetry_profile=if!emergency_fast{config.telemetry_profile}else{iroha_config::parameters::actual::TelemetryProfile::Disabled};"
        ));
        assert!(
            compact_source.contains(
                "if!emergency_fast&&telemetry_profile.metrics_enabled(){start_telemetry(&logger,&config,&telemetry,&mutsupervisor).await;"
            )
        );
        assert!(compact_source.contains(
            "telemetry.metrics_fresh_checked().await.ok().map(iroha_telemetry::telegram::MetricsSnapshot::from_metrics)"
        ));
        assert!(
            compact_source
                .contains("letnts_reservation=iroha_core::time::reserve(iroha_core::time::Params::from(&config.nts,)).ok_or_else(")
        );
        assert!(compact_source.contains(
            "letnts_child=ifconfig_emergency_fast{iroha_core::time::hold_fallback_reserved("
        ));
        assert!(compact_source.contains(
            "}else{iroha_core::time::start_reserved(node.network.clone(),nts_reservation,"
        ));
        let nts_start = compact_source
            .find("iroha_core::time::start_reserved(node.network.clone()")
            .expect("NTS start");
        let os_signal_preflight = compact_source
            .find("setup_shutdown_on_os_signals()")
            .expect("OS signal preflight");
        let publication_preflight = compact_source
            .find("build_and_start_injected_musubi_publication_private_service_v1")
            .expect("private publication preflight");
        assert!(nts_start > os_signal_preflight);
        assert!(nts_start > publication_preflight);
        assert!(compact_source.contains(
            "lettelemetry=ifemergency_fast||!telemetry_profile.metrics_enabled(){iroha_core::telemetry::Telemetry::from(state_telemetry.clone())}else{"
        ));
        assert!(
            compact_source
                .contains("ifemergency_fast{state.validate_restored_governance(&config.gov)")
        );
        assert!(compact_source.contains(
            "}else{apply_state_runtime_config_before_snapshot_auth(&mutstate,&config).map_err(|error|Report::new(error).change_context(StartError::InitKura))?;}"
        ));
        assert!(compact_source.contains(
            "letevents_buffer_capacity=ifemergency_fast{1}else{config.torii.events_buffer_capacity.get()};"
        ));
        assert!(compact_source.contains(
            "letruntime_nexus=ifemergency_fast{iroha_config::parameters::actual::Nexus::default()}else{nexus_for_runtime_surfaces(&state)};"
        ));
        assert!(compact_source.contains(
            "letmutqueue_config=config.queue;ifemergency_fast{queue_config.capacity=std::num::NonZeroUsize::MIN;queue_config.capacity_per_user=std::num::NonZeroUsize::MIN;queue_config.max_retained_bytes=std::num::NonZeroU64::MIN;queue_config.expired_cull_batch=std::num::NonZeroUsize::MIN;}"
        ));
        assert!(compact_source.contains(
            "letconfig_update_receivers=ifemergency_fast{None}else{Some(ConfigUpdateReceivers{"
        ));
        assert!(compact_source.contains(
            "if!emergency_fast&&config.torii.sorafs_storage.reputation_runtime.is_none()&&sorafs_reputation_retention_authority.is_some()"
        ));
        assert!(compact_source.contains(
            "ifletSome(config_update_receivers)=config_update_receivers{letnet_for_relay=network.clone();"
        ));
        assert!(compact_source.contains(
            "if!emergency_fast&&config.telemetry_profile.expensive_metrics_enabled(){letfastpq_device_labels=FastpqDeviceLabels::from_config(&config.zk.fastpq);install_fastpq_execution_mode_probe(&fastpq_device_labels);"
        ));
        assert!(
            compact_source
                .contains("if!args.startup.check_config&&!args.startup.check_storage{ifconfig.kura.init_mode==InitMode::Fast{")
        );
        assert!(compact_source.contains(
            "let_=ivm::apply_stack_sizes(ivm::MIN_STACK_BYTES,ivm::MIN_STACK_BYTES);ivm::set_scheduler_thread_limits(Some(1),Some(1));println!(\"{}\",scheduler_banner_line(1));}else{apply_concurrency_config(&config.concurrency);}}"
        ));
        assert!(compact_source.contains(
            "apply_norito_config(&config);ifconfig.kura.init_mode==InitMode::Fast{norito::core::hw::set_gpu_compression_allowed(false);}"
        ));
        assert!(compact_source.contains(
            "letmutacceleration=config.accel.clone();acceleration.enable_simd=false;acceleration.enable_metal=false;acceleration.enable_cuda=false;acceleration.max_gpus=Some(0);apply_ivm_acceleration_config(&acceleration);rs16::set_simd_enabled(false);"
        ));
        assert!(compact_source.contains(
            "if!emergency_fast{letdeadlock_shutdown=supervisor.shutdown_signal();supervisor.monitor(tokio::spawn(asyncmove{loop{tokio::select!{()=deadlock_shutdown.receive()=>break,()=tokio::time::sleep(Duration::from_secs(10))=>{}}"
        ));
        assert!(compact_source.contains(
            "lettokio_stack_bytes=ifemergency_fast{iroha_config::parameters::actual::Concurrency::from_defaults().tokio_stack_bytes}else{config.concurrency.tokio_stack_bytes};"
        ));
        assert!(compact_source.contains(
            "letgpu_allowed=cfg.kura.init_mode!=InitMode::Fast&&n.allow_gpu_compression;"
        ));
    }
    #[test]
    fn emergency_fast_uses_inert_consensus_and_transaction_gossip_handles() {
        let startup = include_str!("main.rs")
            .split_once("pub(crate) async fn start_with_runtime_deps")
            .expect("runtime-dependency startup entry")
            .1;
        assert!(
            include_str!("startup_preparation.rs")
                .contains("let prepared_sumeragi = if emergency_fast {\n            None")
        );
        let consensus = startup
            .split_once("let sumeragi = match prepared_sumeragi")
            .expect("emergency Fast consensus branch")
            .1
            .split_once("let tx_gossiper = if emergency_fast")
            .expect("transaction-gossip branch")
            .0;
        assert!(consensus.contains("None => {"));
        assert!(consensus.contains("start_on_network"));

        let transaction_gossip = startup
            .split_once("let tx_gossiper = if emergency_fast")
            .expect("emergency Fast transaction-gossip branch")
            .1
            .split_once("if let Some(handle) = sumeragi.as_ref()")
            .expect("snapshot-maker boundary")
            .0;
        assert!(
            transaction_gossip.contains("TransactionGossiperHandle::emergency_fast_disabled()")
        );
        assert!(transaction_gossip.contains("TransactionGossiper::from_config"));

        let compact_source: String = include_str!("main.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert!(
            compact_source
                .contains("lettorii=ifemergency_fast{torii}else{torii.with_p2p(network.clone())};")
        );

        // Fast registers one bounded peer/trust subscriber and nothing else.
        let relay: String = include_str!("network_relay.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert!(relay.contains(
            "letsubscriptions=ifshared.emergency_fast{vec![(SubscriberFilter::topics([Topic::PeerGossip,Topic::TrustGossip]),EMERGENCY_FAST_SUBSCRIBER_CAP,)]}"
        ));
    }
    #[test]
    fn emergency_fast_disables_streaming_persistence_and_control() {
        let compact_source: String = include_str!("main.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let streaming_setup = compact_source
            .split_once("letmutstreaming=iroha_core::streaming::StreamingHandle")
            .expect("streaming setup")
            .1
            .split_once("log_startup_trace(\"irohad.streaming.ready\"")
            .expect("streaming setup boundary")
            .0;
        assert!(streaming_setup.starts_with("::with_key_material"));
        assert!(streaming_setup.contains("ifemergency_fast{"));
        let strict_branch = streaming_setup
            .split_once("}else{")
            .expect("Strict streaming branch")
            .1;
        assert!(strict_branch.contains("streaming.set_snapshot_path("));
        assert!(strict_branch.contains("streaming.load_snapshots()"));

        let relay: String = include_str!("network_relay.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let streaming_control = relay
            .split_once("StreamingControl(frame)=>{")
            .expect("streaming control relay branch")
            .1
            .split_once("TransactionGossiper(data)=>{")
            .expect("streaming control relay boundary")
            .0;
        assert!(streaming_control.contains(
            "if!self.emergency_fast&&letErr(error)=self.streaming.process_control_frame("
        ));
    }
    #[test]
    fn enabled_reputation_runtime_has_no_validator_key_submitter_fallback() {
        let source: String = include_str!("main.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let reputation_startup = source
            .split_once(
                "letsorafs_reputation_runtime=ifletSome(reputation_config)=sorafs_reputation_config.as_ref(){",
            )
            .expect("reputation startup branch")
            .1
            .split_once("letsorafs_hedging_billing_runtime")
            .expect("reputation startup branch boundary")
            .0;
        assert!(
            !reputation_startup.contains("config.common.key_pair"),
            "the standard launcher must never adapt the validator key into reputation authority"
        );
        assert!(
            reputation_startup
                .contains("sorafs_reputation_journal_transaction_submitter_override.ok_or_else"),
            "enabled reputation startup must explicitly require the injected submitter"
        );
        assert!(
            reputation_startup.contains("sorafs_reputation_journal_checkpoint_provider"),
            "enabled reputation startup must pass the injected monotonic journal checkpoint provider"
        );
    }
    #[test]
    fn reputation_runtime_defers_assembly_until_archive_activation() {
        let source: String = include_str!("main.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let reputation_startup = source
            .split_once(
                "letsorafs_reputation_runtime=ifletSome(reputation_config)=sorafs_reputation_config.as_ref(){",
            )
            .expect("reputation startup branch")
            .1
            .split_once("letsorafs_hedging_billing_runtime")
            .expect("reputation startup branch boundary")
            .0;
        assert!(
            reputation_startup
                .contains("letreputation_archive_active=reputation_archive_activation")
                && reputation_startup.contains(".activation_ready()"),
            "reputation startup must evaluate the prepared archive activation gate"
        );
        assert!(
            reputation_startup.contains("sorafs_reputation_runtime::start_deferred"),
            "an unactivated archive must use nonblocking deferred runtime assembly"
        );
        assert!(
            reputation_startup.contains("ReputationRuntimeActivationProbeV1"),
            "deferred assembly must retain the exact prepared activation probe"
        );
    }
    #[test]
    fn configured_appeal_finance_roles_have_exact_ordered_bindings() {
        use iroha_config::parameters::actual::{
            SorafsAppealFinanceCheckpointBinding, SorafsAppealFinanceSignerBinding,
        };
        use iroha_crypto::KeyPair;
        let mut config = Config::from_toml_source(TomlSource::inline(minimal_config_table()))
            .expect("resolve repository default config");
        let signer_a = KeyPair::try_from_seed(vec![0xA1; 32], Algorithm::Ed25519)
            .expect("derive first appeal-finance signer");
        let signer_b = KeyPair::try_from_seed(vec![0xA2; 32], Algorithm::Ed25519)
            .expect("derive rotated appeal-finance signer");
        let checkpoint = KeyPair::try_from_seed(vec![0xA3; 32], Algorithm::Ed25519)
            .expect("derive independent checkpoint signer");
        let appeal_finance = &mut config.torii.sorafs_appeal_finance_settlement;
        appeal_finance.submitter_signers = vec![
            SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-finance-a".to_owned(),
                authority: AccountId::new(signer_a.public_key().clone()),
                public_key: signer_a.public_key().clone(),
                revision: 7,
                policy_digest: [0xA7; 32],
                valid_from_block_height: 1,
                revoked_at_block_height: Some(10),
            },
            SorafsAppealFinanceSignerBinding {
                handle: "provider:appeal-finance-b".to_owned(),
                authority: AccountId::new(signer_b.public_key().clone()),
                public_key: signer_b.public_key().clone(),
                revision: 8,
                policy_digest: [0xA8; 32],
                valid_from_block_height: 10,
                revoked_at_block_height: None,
            },
        ];
        appeal_finance.checkpoint_provider = Some(SorafsAppealFinanceCheckpointBinding {
            handle: "kms:appeal-finance-checkpoint".to_owned(),
            public_key: checkpoint.public_key().clone(),
            revision: 3,
            policy_digest: [0xA3; 32],
        });
        let bindings = IrohaRuntimeProviderBindingsV1::try_from_config(&config)
            .expect("project configured appeal-finance provider bindings");
        let observed: Vec<_> = bindings
            .iter()
            .map(|binding| {
                (
                    binding.slot(),
                    binding.handle().to_owned(),
                    binding.revision(),
                    binding.policy_digest(),
                )
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                (
                    IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner,
                    "provider:appeal-finance-a".to_owned(),
                    Some(7),
                    Some([0xA7; 32]),
                ),
                (
                    IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner,
                    "provider:appeal-finance-b".to_owned(),
                    Some(8),
                    Some([0xA8; 32]),
                ),
                (
                    IrohaRuntimeProviderSlotV1::AppealFinanceCheckpoint,
                    "kms:appeal-finance-checkpoint".to_owned(),
                    Some(3),
                    Some([0xA3; 32]),
                ),
            ]
        );
        assert_eq!(
            bindings
                .iter()
                .filter(|binding| {
                    binding.slot() == IrohaRuntimeProviderSlotV1::AppealFinanceTransactionSigner
                })
                .count(),
            2,
            "multiple bindings for the appeal-finance signer role are intentional"
        );
    }
    #[test]
    fn standard_launcher_resolves_and_forwards_deployment_runtime_dependencies() {
        let compact_source: String = include_str!("main.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let run_main_source = compact_source
            .split_once("fnrun_main(")
            .expect("run_main source")
            .1
            .split_once("fnvalidate_config_and_genesis_for_check(")
            .expect("run_main source boundary")
            .0;
        let run_node_source = compact_source
            .split_once("asyncfnrun_node(")
            .expect("run_node source")
            .1
            .split_once("fnlog_norito_banner(")
            .expect("run_node source boundary")
            .0;
        assert!(
            run_main_source.contains(
                "runtime_provider_registry::resolve_runtime_deps(&config,runtime_provider_registry)"
            ),
            "standard CLI startup must resolve the sanitized deployment registry request"
        );
        assert!(
            run_main_source.contains(
                "(!bindings.is_empty()).then(||{runtime_provider_broker::StockRuntimeProviderBrokerRegistryV1::new(config.runtime_provider_broker.endpoint_path.clone(),)})"
            ),
            "the stock broker registry must use the validated endpoint only for a non-empty binding catalog"
        );
        assert!(
            run_main_source.contains(
                "runtime_provider_registry.or_else(||{stock_runtime_provider_registry.as_ref()"
            ),
            "an explicitly injected deployment registry must remain authoritative"
        );
        assert!(
            run_main_source.contains(
                "rt.block_on(run_node(build,prepared,logger,runtime_deps,musubi_publication_factory,))"
            ),
            "standard CLI startup must forward the resolved dependency set and private publication factory"
        );
        assert!(
            run_node_source.contains(
                "Iroha::activate_with_runtime_deps(build,prepared,logger,shutdown_on_panic.clone(),runtime_deps,musubi_publication_factory,)"
            ),
            "daemon startup must consume the resolved dependency set and private publication factory"
        );
        assert!(
            !run_main_source
                .contains("letruntime_deps=IrohaRuntimeDeps::default();rt.block_on(run_node("),
            "standard CLI startup must not replace registry output with Default"
        );
        let host_boundary = run_main_source
            .split_once("fnprepare_with_runtime_deps(")
            .expect("two-phase host boundary")
            .1;
        let preparation = host_boundary
            .find(".block_on(PreparedStartup::prepare(config,genesis))")
            .expect("one original native preparation");
        let provider = host_boundary
            .find("matchresolve(prepared.config())")
            .expect("out-of-Tokio borrowed provider call");
        let cleanup = host_boundary
            .find("runtime.block_on(prepared.close())")
            .expect("joined original owner on provider refusal");
        assert!(preparation < provider && provider < cleanup);
        let validation = run_main_source
            .find("validate_startup_config_offline(&config).change_context(MainError::Config)?")
            .expect("offline validation in run_main");
        let binding_projection = run_main_source
            .find("IrohaRuntimeProviderBindingsV1::try_from_config(&config)")
            .expect("runtime-provider binding projection in run_main");
        let stock_broker = run_main_source
            .find("StockRuntimeProviderBrokerRegistryV1::new")
            .expect("stock runtime-provider broker construction in run_main");
        let resolution = run_main_source
            .find(
                "runtime_provider_registry::resolve_runtime_deps(&config,runtime_provider_registry)",
            )
            .expect("provider resolution in run_main");
        let runtime_start = run_main_source
            .find("tokio::runtime::Builder::new_multi_thread()")
            .expect("Tokio runtime construction in run_main");
        assert!(
            validation < binding_projection
                && binding_projection < runtime_start
                && runtime_start < stock_broker
                && stock_broker < resolution,
            "pure binding preflight precedes preparation; the host resolves providers after native preparation"
        );
    }
    #[test]
    fn explicit_musubi_private_factory_is_late_bound_and_supervised_fail_closed() {
        let compact_source: String = include_str!("main.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert!(
            compact_source.contains("run_main(build,None,None)"),
            "the stock launcher must not construct or start a private publication service"
        );
        assert!(
            compact_source.contains("run_main(build,Some(registry),None)"),
            "the existing custom registry launcher must preserve fail-closed publication defaults"
        );
        assert!(
            compact_source.contains("run_main(build,None,Some(factory))"),
            "the standalone publication launcher must not require an unrelated provider registry"
        );
        assert!(
            compact_source.contains("run_main(build,Some(registry),Some(factory))"),
            "the combined custom launcher must inject both deployment-owned dependencies and the late-bound publication factory"
        );
        let startup_source = compact_source
            .split_once("pub(crate)asyncfnstart_with_runtime_deps(")
            .expect("start_with_runtime_deps source")
            .1
            .split_once("fnvalidate_membership_snapshot_against_live_peers(")
            .expect("start_with_runtime_deps source boundary")
            .0;
        let sorafs_node_ready = startup_source
            .find("sorafs_node::NodeHandle::try_new_with_policies_and_runtime_deps(")
            .expect("SoraFS node construction");
        let publication_context = startup_source
            .find(
                "musubi_publication_service::MusubiPublicationPrivateServiceContextV1::new(NetworkId::from_genesis_hash(config.genesis.expected_hash),Arc::clone(&state),Arc::clone(&queue),sorafs_node::NodeHandle::clone(sorafs_node),)",
            )
            .expect("private publication context construction");
        let torii_runtime_deps = startup_source
            .find("letruntime_deps=iroha_torii::ToriiRuntimeDeps::new(")
            .expect("Torii runtime dependency construction");
        let signal_setup = startup_source
            .find("supervisor.setup_shutdown_on_os_signals()")
            .expect("OS signal setup");
        let publication_start = startup_source
            .find(
                "musubi_publication_service::build_and_start_injected_musubi_publication_private_service_v1(musubi_publication_factory,musubi_publication_context.expect(\"privateMusubipublicationisdisabledduringemergencyFaststartup\"),supervisor.shutdown_signal(),)",
            )
            .expect("late-bound publication service startup");
        let publication_monitor = startup_source
            .find("ifletSome(child)=publication_child{supervisor.monitor(child);}")
            .expect("publication child supervision");
        let external_signal = startup_source
            .find("supervisor.shutdown_on_external_signal(shutdown_signal)")
            .expect("external shutdown signal hookup");
        assert!(
            sorafs_node_ready < publication_context
                && publication_context < torii_runtime_deps
                && torii_runtime_deps < signal_setup
                && signal_setup < publication_start
                && publication_start < publication_monitor
                && publication_monitor < external_signal,
            "the private factory must receive ready daemon handles after replay, start only after fallible signal setup, and join the node supervisor"
        );
    }
    #[test]
    fn standard_launcher_source_forbids_six_node_key_sorafs_signer_adaptations() {
        let compact_source: String = include_str!("main.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        for builder in [
            "with_sorafs_stream_token_signer_client",
            "with_sorafs_stream_token_state_observer",
            "with_sorafs_stream_token_approved_anchor",
            "with_sorafs_proof_outcome_signer",
            "with_sorafs_repair_transaction_signer",
            "with_sorafs_reserve_transaction_signer",
            "with_sorafs_orderbook_transaction_signer",
            "with_sorafs_moderation_transaction_signer",
        ] {
            let forbidden = [".", builder, "(Arc::new(config.common.key_pair.clone()))"].concat();
            assert!(
                !compact_source.contains(&forbidden),
                "standard launcher must not adapt the node key through {builder}"
            );
        }
    }
    include!("main/runtime_dependency_contract_tests.rs");
    #[test]
    fn standard_launcher_forwards_and_supervises_por_replay_archival() {
        let compact_source: String = include_str!("main.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let clone = compact_source
            .find("runtime_deps.sorafs_por_finalized_replay_archive.clone()")
            .expect("launcher clones the deployment-owned PoR replay archive");
        let inject = compact_source
            .find(".with_por_finalized_replay_archive(Arc::clone(archive))")
            .expect("launcher injects the archive into NodeRuntimeDeps");
        let node = compact_source
            .find("sorafs_node::NodeHandle::try_new_with_policies_and_runtime_deps(")
            .expect("launcher constructs the archive-aware node");
        let reputation = compact_source
            .find("letsorafs_reputation_runtime=ifletSome(reputation_config)")
            .expect("launcher starts the committed reputation runtime");
        let worker = compact_source
            .find("sorafs_por_replay_archive_runtime::start(")
            .expect("launcher starts the supervised reconciliation/compaction worker");
        let reputation_only_worker = compact_source
            .find("sorafs_por_replay_archive_runtime::start_reputation_reconciliation(")
            .expect("launcher starts PoR reputation reconciliation without optional archival");
        assert!(
            clone < inject
                && inject < node
                && node < reputation
                && reputation < worker
                && reputation < reputation_only_worker,
            "the exact archive must enter the node before routes are built, and bounded compaction must start only after durable reputation admission"
        );
        assert!(
            compact_source
                .contains("dynsorafs_node::reputation::runtime::PorTerminalReputationAdmissionV1")
        );
        assert!(
            compact_source.contains("reputation_config.poll_interval,reputation_config.page_items"),
            "the reputation-only callback worker must use validated bounded runtime policy"
        );
    }
    #[test]
    fn standard_launcher_forwards_both_fenced_privacy_roles_to_the_node() {
        let source = include_str!("main.rs");
        let launcher_start = source
            .find("pub(crate) async fn start_with_runtime_deps(")
            .expect("standard launcher function");
        let launcher_end = source[launcher_start..]
            .find("\n    /// Read-only handle to the world state view.")
            .map(|offset| launcher_start + offset)
            .expect("end of standard launcher function");
        let compact_source: String = source[launcher_start..launcher_end]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        for field in [
            "sorafs_fenced_transparency_publisher",
            "sorafs_fenced_transparency_head_reader",
            "sorafs_governance_dag_signer",
            "sorafs_governance_dag_checkpoint_store",
        ] {
            assert!(
                compact_source.contains(&["runtime_deps.", field, ".clone()"].concat()),
                "standard launcher must clone deployment-owned `{field}`"
            );
        }
        let writer = compact_source
            .find(".with_fenced_transparency_publisher(Arc::clone(publisher))")
            .expect("launcher forwards the fused privacy writer");
        let reader = compact_source
            .find(".with_fenced_transparency_head_reader(Arc::clone(reader))")
            .expect("launcher forwards the authenticated head reader");
        let signer = compact_source
            .find(".with_governance_dag_signer(Arc::clone(signer))")
            .expect("launcher forwards the signed Governance DAG publisher");
        let checkpoint_store = compact_source
            .find(".with_governance_dag_checkpoint_store(Arc::clone(checkpoint_store))")
            .expect("launcher forwards the sealed Governance DAG producer checkpoint store");
        let node = compact_source
            .find("sorafs_node::NodeHandle::try_new_with_policies_and_runtime_deps(")
            .expect("launcher constructs the embedded SoraFS node");
        assert!(
            writer < reader
                && reader < signer
                && signer < checkpoint_store
                && checkpoint_store < node,
            "the fused privacy role pair, signed Governance publisher, and sealed producer store must enter NodeRuntimeDeps before node construction"
        );
        let torii_deps = compact_source
            .find("letruntime_deps=iroha_torii::ToriiRuntimeDeps::new(")
            .expect("launcher assembles Torii dependencies");
        let torii_start = compact_source[torii_deps..]
            .find("lettorii=Torii::new_with_handle(")
            .map(|offset| torii_deps + offset)
            .expect("launcher constructs Torii");
        assert!(
            !compact_source[torii_deps..torii_start]
                .contains("with_sorafs_governance_dag_checkpoint_store"),
            "irohad must retain the raw producer checkpoint store inside its prebuilt node instead of injecting it into Torii a second time"
        );
    }
    include!("main/governance_dag_launcher_tests.rs");
    #[test]
    fn standard_launcher_configures_kura_proof_limits_before_start() {
        let compact_source: String = include_str!("startup_preparation.rs")
            .chars()
            .chain(include_str!("main.rs").chars())
            .filter(|character| !character.is_whitespace())
            .collect();
        let construct = compact_source
            .find("Kura::new_with_configured_lane_catalog(")
            .expect("standard launcher constructs Kura");
        let configure = compact_source
            .find("kura.configure_fastpq_proof_sidecar_limits(&config.zk.fastpq)")
            .expect("standard launcher applies configured proof-sidecar limits");
        let start = compact_source
            .find("Kura::start(kura.clone(),supervisor.shutdown_signal())")
            .expect("standard launcher starts Kura");
        assert!(
            construct < configure && configure < start,
            "Kura proof-sidecar limits must be configured before its runtime starts"
        );
    }
    #[test]
    fn standard_launcher_pop_runtime_uses_only_config_and_the_injected_registry() {
        let compact_source: String = include_str!("main.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let corridor = compact_source
            .split_once(
                "letsorafs_pop_credentials=ifemergency_fast{None}else{sorafs_pop_runtime::build(",
            )
            .map(|(_, suffix)| suffix)
            .expect("standard launcher must build the PoP runtime");
        let corridor = corridor
            .split_once("//Diagnosticssharethenode'soriginalshutdownowner.")
            .map(|(corridor, _)| corridor)
            .expect("PoP startup corridor must end before daemon subsystem startup");
        assert!(
            corridor.starts_with(
                "config.torii.sorafs_storage.pop_credentials.as_ref(),runtime_deps.sorafs_pop_credential_provider_registry.clone(),)"
            ),
            "PoP startup must use only public config and the injected registry"
        );
        for forbidden in [
            "config.common.key_pair",
            "private_key",
            "std::env",
            "env::",
            "std::fs",
            "fs::",
            "SystemTime",
            "PopCredentialRuntimeSecretsV1",
            "PopCredentialToriiRuntimeV1::open",
        ] {
            assert!(
                !corridor.contains(forbidden),
                "standard PoP startup corridor must not contain `{forbidden}`"
            );
        }
    }
    mod scheduler_banner {
        use super::*;
        #[test]
        fn formats_core_count() {
            assert_eq!(scheduler_banner_line(1), "Using 1 core");
            assert_eq!(scheduler_banner_line(4), "Using 4 cores");
        }
        #[test]
        fn clamps_zero_to_one_core() {
            assert_eq!(scheduler_banner_line(0), "Using 1 core");
        }
    }
    mod replay_startup_config {
        use super::*;
        #[test]
        fn installs_actual_zk_and_settlement_config_before_kura_replay() {
            let mut config_table = crate::config_tests::minimal_config_table();
            iroha_config::base::toml::Writer::new(&mut config_table)
                .write(
                    ["genesis", "public_key"],
                    "ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4",
                )
                .write(["genesis", "file"], "./genesis.signed.nrt");
            let mut config = ConfigReader::new()
                .with_toml_source(TomlSource::inline(config_table))
                .read_and_complete::<UserConfig>()
                .expect("sample config should be readable")
                .parse()
                .expect("sample config should parse");
            config.zk.sccp.max_proofs_per_transaction =
                std::num::NonZeroU32::new(7).expect("nonzero proof cap");
            config.zk.sccp.max_proof_bytes_per_proof =
                std::num::NonZeroU64::new(11).expect("nonzero byte cap");
            config.settlement.router.epsilon_bps = 17;
            config.pipeline.ivm_execution_max_bytes = 1024;
            let kura = Kura::blank_kura_for_testing();
            let query = LiveQueryStore::start_test();
            let mut state = State::new_for_testing(World::new(), kura, query);
            let original_execution_budget = state.ivm_execution_budget();
            install_zk_config_before_kura_replay(&mut state, &config)
                .expect("fresh state accepts actual ZK configuration");
            apply_state_runtime_config_before_snapshot_auth(&mut state, &config)
                .expect("fresh state accepts runtime configuration");
            assert!(original_execution_budget.same_pool(&state.ivm_execution_budget()));
            assert_eq!(original_execution_budget.limit_bytes(), 1024);
            let installed = state.zk_snapshot();
            // The node configuration cannot change a validity value: the protocol
            // default (or the committed `zk_validity_policy_v1`) decides it.
            let protocol = iroha_core::state::default_zk_config();
            assert_ne!(
                config.zk.sccp.max_proofs_per_transaction,
                protocol.sccp.max_proofs_per_transaction
            );
            assert_eq!(
                installed.sccp.max_proofs_per_transaction,
                protocol.sccp.max_proofs_per_transaction
            );
            assert_eq!(
                installed.sccp.max_proof_bytes_per_proof,
                protocol.sccp.max_proof_bytes_per_proof
            );
            assert_eq!(
                iroha_core::state::compute_zk_consensus_policy_hash(&installed),
                iroha_core::state::compute_zk_consensus_policy_hash(&protocol),
                "a node-local ZK setting must not move the consensus policy hash"
            );
            assert_eq!(
                state.settlement().router.epsilon_bps,
                17,
                "the exact settlement router policy must be installed before Kura replay",
            );
        }
    }
    mod fastpq_overrides {
        use super::*;
        use iroha_config::parameters::actual::{Fastpq, FastpqExecutionMode, FastpqPoseidonMode};
        #[test]
        fn maps_metal_overrides_from_config() {
            let cfg = Fastpq {
                execution_mode: FastpqExecutionMode::Cpu,
                poseidon_mode: FastpqPoseidonMode::Cpu,
                proof_sidecar_queue_cap:
                    iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
                proof_sidecar_max_bytes:
                    iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
                proof_sidecar_max_retries:
                    iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
                device_class: None,
                chip_family: None,
                gpu_kind: None,
                metal_queue_fanout: None,
                metal_queue_column_threshold: None,
                metal_max_in_flight: Some(8),
                metal_threadgroup_width: Some(128),
                metal_trace: true,
                metal_debug_enum: true,
            };
            let overrides = fastpq_metal_overrides_from_config(&cfg);
            assert_eq!(overrides.max_in_flight, Some(8));
            assert_eq!(overrides.threadgroup_size, Some(128));
            assert!(overrides.dispatch_trace);
            assert!(overrides.debug_enum);
        }
        #[cfg(feature = "fastpq-gpu")]
        #[test]
        fn poseidon_word_preflight_respects_fastpq_config() {
            let mut cfg = Fastpq {
                execution_mode: FastpqExecutionMode::Cpu,
                poseidon_mode: FastpqPoseidonMode::Cpu,
                proof_sidecar_queue_cap:
                    iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
                proof_sidecar_max_bytes:
                    iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
                proof_sidecar_max_retries:
                    iroha_config::parameters::defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
                device_class: None,
                chip_family: None,
                gpu_kind: None,
                metal_queue_fanout: None,
                metal_queue_column_threshold: None,
                metal_max_in_flight: None,
                metal_threadgroup_width: None,
                metal_trace: false,
                metal_debug_enum: false,
            };
            assert!(!fastpq_poseidon_word_preflight_enabled(&cfg));
            cfg.poseidon_mode = FastpqPoseidonMode::Gpu;
            assert!(fastpq_poseidon_word_preflight_enabled(&cfg));
            cfg.poseidon_mode = FastpqPoseidonMode::Cpu;
            assert!(!fastpq_poseidon_word_preflight_enabled(&cfg));
        }
    }
    mod torii_receipt_signer_selection {
        use super::*;
        #[test]
        fn default_is_stable_and_domain_separated_from_node_identity() {
            let node = KeyPair::random_with_algorithm(Algorithm::Ed25519);
            let first = torii_receipt_signer_or_derived(None, &node)
                .expect("checked receipt signer derivation should succeed");
            let second = torii_receipt_signer_or_derived(None, &node)
                .expect("checked receipt signer derivation should be repeatable");
            assert_eq!(first.algorithm(), Algorithm::Secp256k1);
            assert_eq!(first.public_key(), second.public_key());
            assert_ne!(first.public_key(), node.public_key());
        }
        #[test]
        fn different_node_identities_derive_different_receipt_signers() {
            let first_node = KeyPair::random_with_algorithm(Algorithm::Ed25519);
            let second_node = KeyPair::random_with_algorithm(Algorithm::Ed25519);
            let first = torii_receipt_signer_or_derived(None, &first_node)
                .expect("first checked receipt signer derivation should succeed");
            let second = torii_receipt_signer_or_derived(None, &second_node)
                .expect("second checked receipt signer derivation should succeed");
            assert_ne!(first.public_key(), second.public_key());
        }
        #[test]
        fn preserves_configured_receipt_signer() {
            let configured = KeyPair::random_with_algorithm(Algorithm::Ed25519);
            let unrelated_node = KeyPair::random_with_algorithm(Algorithm::Ed25519);
            let signer = torii_receipt_signer_or_derived(Some(configured.clone()), &unrelated_node)
                .expect("configured receipt signer should not require derivation");
            assert_eq!(signer.public_key(), configured.public_key());
            assert_eq!(signer.algorithm(), Algorithm::Ed25519);
        }
    }
    mod norito_archive_len {
        use super::*;
        fn base_config() -> Config {
            let table = crate::config_tests::minimal_config_table();
            Config::from_toml_source(TomlSource::inline(table)).expect("base config")
        }
        #[test]
        fn resolves_to_network_frame_when_larger() {
            let mut config = base_config();
            config.norito.max_archive_len = 32 * 1024 * 1024;
            config.network.max_frame_bytes = 128 * 1024 * 1024;
            let resolved = resolve_norito_max_archive_len(&config);
            assert_eq!(resolved, 128 * 1024 * 1024);
        }
        #[test]
        fn preserves_requested_when_already_largest() {
            let mut config = base_config();
            config.norito.max_archive_len = 256 * 1024 * 1024;
            config.network.max_frame_bytes = 64 * 1024 * 1024;
            let resolved = resolve_norito_max_archive_len(&config);
            assert_eq!(resolved, 256 * 1024 * 1024);
        }
    }
    #[cfg(feature = "telemetry")]
    mod metrics_bootstrap {
        use serial_test::serial;
        use std::sync::Arc;
        #[test]
        #[serial]
        fn init_global_metrics_handle_is_idempotent() {
            let first = super::init_global_metrics_handle(false);
            let second = super::init_global_metrics_handle(false);
            assert!(Arc::ptr_eq(&first, &second));
        }
    }
    mod cli_args {
        #[allow(unused_imports)]
        use super::*;
        #[test]
        fn inrou_deployment_authority_requires_offline_check_config() {
            let flag = "--require-genesis-inrou-deployment-authority";
            let error = Args::try_parse_from(["iroha3d", flag, "public-account"])
                .expect_err("deployment qualification must not become a runtime option");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
            let parsed =
                Args::try_parse_from(["iroha3d", "--check-config", flag, "public-account"])
                    .expect("account parsing is deferred until the configured chain is known");
            assert_eq!(
                parsed
                    .startup
                    .require_genesis_inrou_deployment_authority
                    .as_deref(),
                Some("public-account"),
            );
        }
        #[test]
        fn version_is_supplied_by_the_executable() {
            let build = CompiledBuildMetadata::from_compiled_parts(
                "executable-version",
                Some("local-fast-build"),
                None,
                None,
                None,
                None,
            );
            let error = args_command(build)
                .try_get_matches_from(["iroha3d", "--version"])
                .expect_err("version display exits through clap");
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
            assert_eq!(error.render().to_string(), "iroha3d executable-version\n");
        }
        #[test]
        fn whitespace_only_arguments_are_ignored() {
            let parsed = parse_args_from(
                test_build_metadata(),
                vec![
                    OsString::from("iroha3d"),
                    OsString::from(" "),
                    OsString::from("--trace-config"),
                ],
            );
            assert!(parsed.startup.trace_config);
        }
        #[test]
        fn surrounding_whitespace_is_trimmed() {
            let parsed = parse_args_from(
                test_build_metadata(),
                vec![
                    OsString::from("iroha3d"),
                    OsString::from("   --trace-config  "),
                ],
            );
            assert!(parsed.startup.trace_config);
        }
        #[test]
        fn meaningful_arguments_are_preserved() {
            let parsed = parse_args_from(
                test_build_metadata(),
                vec![
                    OsString::from("iroha3d"),
                    OsString::from("--config"),
                    OsString::from("config.toml"),
                ],
            );
            assert_eq!(
                parsed.config,
                Some(PathBuf::from("config.toml")),
                "config argument should remain untouched"
            );
        }
    }
    mod manifest_crypto_checks {
        use super::*;
        use iroha_config::base::toml::TomlSource;
        use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry, ManifestCrypto};
        use iroha_model_base::chain::ChainId;
        fn sample_manifest() -> RawGenesisTransaction {
            complete_test_genesis_builder(GenesisBuilder::new_without_executor(
                ChainId::from("test-chain"),
                PathBuf::from("."),
            ))
            .build_raw()
            .expect("build complete sample genesis manifest")
        }
        fn sample_config_table() -> toml::Table {
            // Share the daemon's complete parser fixture, including independent
            // consensus, transport and streaming identities. Keep only these
            // manifest-test overrides here so required config fields cannot drift.
            let mut table = crate::config_tests::minimal_config_table();
            iroha_config::base::toml::Writer::new(&mut table)
                .write(
                    ["genesis", "public_key"],
                    "ed01204164BF554923ECE1FD412D241036D863A6AE430476C898248B8237D77534CFC4",
                )
                .write(["genesis", "file"], "./genesis.signed.nrt")
                .write(["logger", "format"], "pretty")
                .write(
                    ["nexus", "storage", "local_budget_bytes"],
                    1_073_741_824_i64,
                );
            table
        }
        fn sample_config() -> Config {
            ConfigReader::new()
                .with_toml_source(TomlSource::inline(sample_config_table()))
                .read_and_complete::<UserConfig>()
                .expect("sample config should be readable")
                .parse()
                .expect("sample config should parse")
        }
        fn configure_exact_moderation_strict_ingress(config: &mut Config) {
            let qualification = iroha_torii::sorafs::moderation_runtime::
                torii_moderation_strict_ingress_qualification_v1();
            let authority = AccountId::new(config.common.key_pair.public_key().clone());
            config.torii.sorafs_storage.moderation_orchestrator = Some(
                iroha_config::parameters::actual::SorafsModerationOrchestrator {
                    checkpoint_path: "/var/lib/iroha/sorafs/moderation.to".into(),
                    checkpoint_store_handle: "sealed:moderation:checkpoint-primary".into(),
                    checkpoint_store_revision: 1,
                    checkpoint_store_policy_digest: [0x81; 32],
                    checkpoint_store_attestation_public_key: [
                        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a,
                        0xa7, 0x4d, 0x1b, 0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4,
                        0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
                    ],
                    maintenance_authority: authority,
                    transaction_signer_handle: "provider:moderation:signer-primary".into(),
                    transaction_signer_revision: 1,
                    transaction_signer_policy_digest: [0x82; 32],
                    strict_ingress_handle: iroha_torii::sorafs::moderation_runtime::
                        TORII_MODERATION_STRICT_INGRESS_HANDLE_V1.into(),
                    strict_ingress_revision: qualification.revision(),
                    strict_ingress_policy_digest: qualification.policy_digest(),
                    settlement_handoff_handle: "queue:moderation:settlement-primary".into(),
                    settlement_handoff_revision: 1,
                    settlement_handoff_policy_digest: [0x83; 32],
                    publication_handoff_handle: "dag:moderation:publication-primary".into(),
                    publication_handoff_revision: 1,
                    publication_handoff_policy_digest: [0x84; 32],
                    panel_notification_handle: "queue:moderation:notification-primary".into(),
                    panel_notification_revision: 1,
                    panel_notification_policy_digest: [0x85; 32],
                    panel_notification_archive_handle:
                        "object-lock:moderation:notification-receipts-primary".into(),
                    panel_notification_archive_revision: 1,
                    panel_notification_archive_policy_digest: [0x86; 32],
                    panel_notification_archive_id: [0x87; 32],
                    panel_notification_archive_bootstrap_public_key: [
                        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
                        0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
                        0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
                    ],
                    panel_notification_archive_public_key: [
                        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
                        0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
                        0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
                    ],
                    panel_notification_archive_predecessor_revocation_generation: None,
                    panel_notification_archive_predecessor_authorization_signature: None,
                    panel_notification_archive_new_key_possession_signature: None,
                    max_cases: 8,
                    max_events: 16,
                    max_outbox_entries: 8,
                    max_idempotency_records: 16,
                    max_handoffs: 8,
                    max_submit_attempts: 2,
                    checkpoint_max_bytes: iroha_config_base::util::Bytes(1024 * 1024),
                    panel_notification_archive_max_bytes: iroha_config_base::util::Bytes(
                        5 * 1024 * 1024,
                    ),
                    worker_interval: std::time::Duration::from_secs(1),
                    maintenance_batch_limit: 4,
                },
            );
        }
        fn sign_configured_genesis_for_test(
            genesis: RawGenesisTransaction,
            genesis_authority: &KeyPair,
            config: &Config,
        ) -> GenesisBlock {
            // Match Kagami's signer: provisional staging and the final proposal
            // commit to the protocol-default ZK policy the genesis block runs under.
            genesis
                .with_consensus_meta()
                .expect("valid fixture consensus parameters")
                .build_and_sign_with_da_proof_policies_and_confidential_policy_hash(
                    genesis_authority,
                    Some(iroha_core::da::proof_policy_bundle(
                        &config.nexus.lane_config,
                    )),
                    Some(iroha_core::state::default_genesis_confidential_policy_hash()),
                )
                .expect("sign genesis fixture with configured DA and confidential policies")
        }
        fn staged_context_hashes_for_test(
            raw: &RawGenesisTransaction,
            signer: &KeyPair,
            config: &Config,
        ) -> (Hash, Hash) {
            // Derive only an unpublished signing draft's policy commitments.
            // The final signed block must pass the unchanged native validator.
            let provisional = sign_configured_genesis_for_test(raw.clone(), signer, config);
            let root = DisposableValidationRoot::create().expect("temporary genesis storage");
            let kura = open_disposable_validation_kura(config, &root).expect("genesis Kura");
            let budget =
                iroha_allocation::AllocationBudget::new(config.pipeline.ivm_execution_max_bytes);
            let mut world = World::try_with_execution_budget(
                [genesis_domain(signer.public_key().clone())],
                [genesis_account(signer.public_key().clone())],
                [],
                &budget,
            )
            .expect("completed genesis World initialization");
            iroha_core::sns::seed_genesis_alias_bootstrap(
                &mut world,
                &provisional.0,
                &config.nexus.dataspace_catalog,
            )
            .expect("authenticated genesis SNS bootstrap");
            let mut state = State::try_new_with_chain_and_network_id(
                budget,
                world,
                kura,
                LiveQueryStore::start_test(),
                config.common.chain.clone(),
                NetworkId::from_genesis_hash(provisional.0.hash()),
                #[cfg(feature = "telemetry")]
                StateTelemetry::default(),
            )
            .expect("genesis state");
            install_zk_config_before_kura_replay(&mut state, config).expect("genesis ZK policy");
            apply_state_runtime_config_before_snapshot_auth(&mut state, config)
                .expect("genesis runtime configuration");
            let baseline = freeze_lane_manifests_for_startup_replay(&config.nexus)
                .expect("genesis lane manifests");
            let policies = install_lane_policies_for_startup_replay(
                &mut state,
                config.nexus.clone(),
                &baseline,
            )
            .expect("genesis lane policy");
            apply_state_geometry_config_before_kura_replay(&mut state, &policies)
                .expect("genesis geometry");
            let voters = iroha_core::sumeragi::schedule::genesis_validators(&provisional)
                .expect("signed genesis voters");
            let topology = Topology::new(voters.into_keys());
            let (mode, context) =
                signed_genesis_context_metadata(&provisional.0).expect("signed genesis mode");
            match ValidBlock::validate_signed_genesis(
                provisional.0,
                &topology,
                &AccountId::new(signer.public_key().clone()),
                &TimeSource::new_system(),
                &state,
                mode,
                context.root_scope,
            )
            .unpack(|_| {})
            {
                Ok((_, staged)) => (
                    iroha_core::sumeragi::staged_genesis_nexus_amx_context_hash(&staged),
                    iroha_core::sumeragi::staged_genesis_execution_policy_hash(&staged)
                        .expect("executed genesis policy"),
                ),
                Err((_, error)) => match *error {
                    iroha_core::block::BlockValidationError::GenesisPolicyMismatch {
                        actual_nexus,
                        actual_execution,
                        ..
                    } => (actual_nexus, actual_execution),
                    error => panic!("genesis signing draft failed native validation: {error}"),
                },
            }
        }
        #[test]
        fn snapshot_signing_identity_matches_configured_restart_verification() {
            let mut config = sample_config();
            assert_eq!(
                snapshot_signing_key(&config).unwrap(),
                config.common.key_pair
            );
            let custom = KeyPair::from_seed(vec![0x47; 32], Algorithm::Ed25519);
            config.snapshot.signing_private_key = Some(custom.private_key().clone());
            assert!(snapshot_signing_key(&config).is_err());
            config.snapshot.verification_public_key = Some(custom.public_key().clone());
            assert_eq!(snapshot_signing_key(&config).unwrap(), custom);
            config.snapshot.signing_private_key = None;
            assert!(snapshot_signing_key(&config).is_err());
        }
        #[test]
        fn manifest_crypto_matches_config() {
            let manifest = sample_manifest();
            let config = sample_config();
            ensure_manifest_crypto_matches(&manifest, &config)
                .expect("expected manifest and config to match");
        }
        #[test]
        fn detects_hash_mismatch() {
            let manifest = sample_manifest();
            let mut config = sample_config();
            config.crypto.default_hash = "sm3-256".to_owned();
            let err = ensure_manifest_crypto_matches(&manifest, &config)
                .expect_err("hash mismatch should be detected");
            assert!(
                err.contains("default_hash"),
                "error should mention hash: {err}"
            );
        }
        #[test]
        fn detects_allowed_signing_mismatch() {
            let mut manifest = sample_manifest();
            let crypto = ManifestCrypto {
                allowed_signing: vec![Algorithm::Ed25519],
                allowed_curve_ids: vec![iroha_data_model::account::curve::CurveId::ED25519.as_u8()],
                ..Default::default()
            };
            crypto
                .validate()
                .expect("mismatched manifest policy must be valid");
            manifest = manifest
                .into_builder()
                .with_crypto(crypto)
                .build_raw()
                .expect("rebuild complete sample genesis manifest");
            let config = sample_config();
            let err = ensure_manifest_crypto_matches(&manifest, &config)
                .expect_err("allowed signing mismatch should be detected");
            assert!(
                err.contains("allowed_signing"),
                "error should mention allowed_signing mismatch: {err}"
            );
        }
        #[test]
        fn detects_allowed_curve_ids_mismatch() {
            let manifest = sample_manifest();
            let mut config = sample_config();
            config.crypto.allowed_curve_ids =
                vec![iroha_data_model::account::curve::CurveId::ED25519.as_u8()];
            let err = ensure_manifest_crypto_matches(&manifest, &config)
                .expect_err("curve id mismatch should be detected");
            assert!(
                err.contains("allowed_curve_ids"),
                "error should mention allowed_curve_ids mismatch: {err}"
            );
        }
        #[test]
        fn verify_genesis_metadata_rejects_crypto_mismatch_in_block() -> eyre::Result<()> {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let mut config = sample_config();
            let genesis_keys = config.common.key_pair.clone();
            let chain = config.common.chain.clone();
            let manifest = complete_test_genesis_builder(GenesisBuilder::new_without_executor(
                chain.clone(),
                PathBuf::from("."),
            ))
            .build_raw()
            .expect("build complete crypto-mismatch genesis manifest")
            .with_consensus_meta()?;
            let genesis_block = manifest.build_and_sign(&genesis_keys)?;
            let mut instructions = Vec::new();
            for tx in genesis_block.0.external_transactions() {
                if let Executable::Instructions(batch) = tx.instructions() {
                    instructions.extend(batch.iter().cloned());
                }
            }
            let handshake_meta = instructions
                .iter()
                .filter_map(|instr| instr.as_any().downcast_ref::<SetParameter>())
                .find_map(|set| {
                    if let Parameter::Custom(custom) = set.inner()
                        && custom.id() == &consensus_metadata::handshake_meta_id()
                    {
                        decode_consensus_handshake_meta(custom.payload()).ok()
                    } else {
                        None
                    }
                })
                .expect("handshake meta should be present in genesis");
            let (mode, mode_tag) = match handshake_meta.mode {
                iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned => (
                    iroha_data_model::block::consensus::ConsensusMode::Permissioned,
                    iroha_core::sumeragi::consensus::PERMISSIONED_TAG.to_string(),
                ),
                iroha_data_model::parameter::system::SumeragiConsensusMode::Npos => (
                    iroha_data_model::block::consensus::ConsensusMode::Npos,
                    iroha_core::sumeragi::consensus::NPOS_TAG.to_string(),
                ),
            };
            let proto = handshake_meta.wire_protocol_version;
            let consensus_fingerprint = handshake_meta.consensus_fingerprint.into_bytes();
            let config_caps = build_consensus_config_caps(&config.nexus, None, None)
                .map_err(|err| eyre::eyre!(format!("{err:?}")))?;
            let consensus_caps = iroha_p2p::ConsensusHandshakeCaps {
                mode,
                proto_version: proto,
                consensus_fingerprint,
                config: config_caps,
            };
            config.genesis.public_key = genesis_keys.public_key().clone();
            config.common.chain = chain;
            config.common.key_pair = genesis_keys.clone();
            config.crypto.allowed_signing = vec![Algorithm::Ed25519];
            let err =
                verify_genesis_metadata(&genesis_block, &config, &consensus_caps, &mode_tag, proto)
                    .expect_err("crypto mismatch should be detected");
            let report = format!("{err:?}");
            assert!(
                report.contains("crypto manifest") || report.contains("crypto mismatch"),
                "unexpected error: {report}"
            );
            Ok(())
        }
        #[test]
        fn genesis_validation_accepts_bls_controllers_when_crypto_config_applied() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let bls_keypair = KeyPair::from_seed(vec![0xBA; 32], Algorithm::BlsNormal);
            let fixture = offline_semantic_genesis_fixture([Register::account(Account::new(
                AccountId::new(bls_keypair.public_key().clone()),
            ))
            .into()]);
            validate_genesis_execution_offline(
                &fixture.config,
                &fixture.genesis,
                &fixture.authority,
                fixture.mode,
                fixture.parameters,
                fixture.cadence_ms,
                None,
            )
            .expect("configured BLS controller registers through native signed genesis execution");
        }

        include!("startup_preparation_tests.rs");

        struct LocalSemanticGenesisFixture {
            config: Config,
            genesis: GenesisBlock,
            authority: AccountId,
            mode: iroha_data_model::block::consensus::ConsensusMode,
            parameters: iroha_data_model::block::consensus::SumeragiGenesisContextParameters,
            cadence_ms: u64,
        }
        fn offline_semantic_genesis_fixture(
            extra_instructions: impl IntoIterator<Item = InstructionBox>,
        ) -> LocalSemanticGenesisFixture {
            let mut config = sample_config();
            let chain_id = ChainId::from("offline-genesis-validation-test");
            let genesis_authority = iroha_crypto::KeyPair::try_from_seed(
                b"offline-genesis-validation-authority".to_vec(),
                Algorithm::Ed25519,
            )
            .expect("deterministic genesis authority");
            let topology = (0_u8..4)
                .map(|index| {
                    let key = iroha_crypto::KeyPair::try_from_seed(
                        vec![0x50 + index; 32],
                        Algorithm::BlsNormal,
                    )
                    .expect("deterministic BLS validator");
                    let pop = iroha_crypto::bls_normal_pop_prove(key.private_key())
                        .expect("BLS proof of possession");
                    GenesisTopologyEntry::new(PeerId::new(key.public_key().clone()), pop)
                })
                .collect();
            let authority = AccountId::new(genesis_authority.public_key().clone());
            config.common.chain = chain_id.clone();
            config.genesis.public_key = genesis_authority.public_key().clone();
            if !config
                .crypto
                .allowed_signing
                .contains(&Algorithm::BlsNormal)
            {
                config.crypto.allowed_signing.push(Algorithm::BlsNormal);
            }
            config.crypto.allowed_curve_ids = config
                .crypto
                .allowed_signing
                .iter()
                .filter_map(|algorithm| {
                    iroha_data_model::account::curve::CurveId::try_from_algorithm(*algorithm).ok()
                })
                .map(iroha_data_model::account::curve::CurveId::as_u8)
                .collect();
            config.crypto.allowed_curve_ids.sort_unstable();
            config.crypto.allowed_curve_ids.dedup();
            let base_genesis = complete_test_genesis_builder_for_topology(
                // Sign the actual policy installed in the staging and target State, including
                // the BLS controllers required by this fixture's four-validator roster.
                GenesisBuilder::new_without_executor(chain_id, ".").with_crypto(ManifestCrypto {
                    sm_openssl_preview: config.crypto.enable_sm_openssl_preview,
                    sm_intrinsics: config.crypto.sm_intrinsics.as_str().to_owned(),
                    default_hash: config.crypto.default_hash.clone(),
                    allowed_signing: config.crypto.allowed_signing.clone(),
                    sm2_distid_default: config.crypto.sm2_distid_default.clone(),
                    allowed_curve_ids: config.crypto.allowed_curve_ids.clone(),
                }),
                topology,
            );
            let base_raw = base_genesis
                .build_raw()
                .expect("build complete offline semantic genesis manifest");
            ensure_manifest_crypto_matches(&base_raw, &config)
                .expect("sign the exact configured crypto policy before native staging");
            let (context_hash, execution_policy_hash) =
                staged_context_hashes_for_test(&base_raw, &genesis_authority, &config);
            let mut parameters = base_raw.sumeragi_context_parameters();
            parameters.nexus_amx_context_hash = context_hash.into();
            parameters.execution_policy_hash = execution_policy_hash.into();
            let mut builder = base_raw
                .into_builder()
                .with_sumeragi_context_parameters(parameters);
            // These fixtures add ordinary world-state instructions only; they
            // deliberately do not alter the signed Nexus/AMX projection.
            for instruction in extra_instructions {
                builder = builder.append_instruction(instruction);
            }
            let genesis = sign_configured_genesis_for_test(
                builder.build_raw().expect("build final genesis fixture"),
                &genesis_authority,
                &config,
            );
            config.genesis.expected_hash = genesis.0.hash();
            let (mode, parameters) = signed_genesis_context_metadata(&genesis.0)
                .expect("signed genesis context metadata");
            let config_caps = build_consensus_config_caps(&config.nexus, None, None)
                .expect("default consensus config caps");
            let (_, _, _, cadence_ms, _) = consensus_caps_from_genesis(&genesis, &config_caps)
                .expect("canonical genesis consensus metadata");
            LocalSemanticGenesisFixture {
                config,
                genesis,
                authority,
                mode,
                parameters,
                cadence_ms,
            }
        }
        #[test]
        fn check_config_offline_executes_available_genesis() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let fixture = offline_semantic_genesis_fixture([]);
            let bootstrap = validate_genesis_execution_offline(
                &fixture.config,
                &fixture.genesis,
                &fixture.authority,
                fixture.mode,
                fixture.parameters,
                fixture.cadence_ms,
                None,
            )
            .expect("valid genesis should execute in the disposable overlay");
            assert_eq!(bootstrap.initial_committee_size, 4);
        }
        /// `--check-config --json` with a local signed genesis reports `ready` and exactly the
        /// genesis-bound values the running network attests: the signed context hashes, the
        /// handshake configuration fingerprint and the build/configuration-bound values of the
        /// `pending` report.
        #[test]
        fn check_config_json_reports_the_signed_genesis_compatibility_values() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let fixture = offline_semantic_genesis_fixture([]);
            // The authenticated bootstrap `--check-config` hands the probe for a local genesis.
            let bootstrap = validate_genesis_execution_offline(
                &fixture.config,
                &fixture.genesis,
                &fixture.authority,
                fixture.mode,
                fixture.parameters,
                fixture.cadence_ms,
                None,
            )
            .expect("the signed genesis executes offline");
            let ready = compatibility_probe::config_compatibility_v1(
                &fixture.config,
                Some((&fixture.genesis, &bootstrap)),
                test_build_metadata(),
            )
            .expect("ready compatibility values");
            let pending = compatibility_probe::config_compatibility_v1(
                &fixture.config,
                None,
                test_build_metadata(),
            )
            .expect("pending compatibility values");
            let hex_hash = |hash: iroha_crypto::Hash| {
                let bytes: &[u8; iroha_crypto::Hash::LENGTH] = hash.as_ref();
                hex::encode(bytes)
            };
            assert_eq!(ready.status, "ready");
            assert_eq!(pending.status, "pending");
            assert_eq!(pending.node_identity, None);
            assert_eq!(ready.diagnostic_build, pending.diagnostic_build);
            assert_eq!(
                ready.node_identity.as_ref().unwrap().initial_committee_size,
                bootstrap.initial_committee_size as u64
            );
            assert_eq!(
                ready.execution_policy_hash,
                Some(hex::encode(fixture.parameters.execution_policy_hash))
            );
            assert_eq!(
                ready.nexus_amx_context_hash,
                Some(hex::encode(fixture.parameters.nexus_amx_context_hash))
            );
            assert_eq!(
                ready.execution_policy_hash,
                Some(hex_hash(bootstrap.execution_policy_hash))
            );
            assert_eq!(
                ready.nexus_amx_context_hash,
                Some(hex_hash(bootstrap.nexus_amx_context_hash))
            );
            let config_caps = build_consensus_config_caps(&fixture.config.nexus, None, None)
                .expect("default consensus config caps");
            let (_, _, handshake, _, _) =
                consensus_caps_from_genesis(&fixture.genesis, &config_caps)
                    .expect("canonical genesis consensus metadata");
            assert_ne!(handshake.config.native_config_fingerprint, [0; 32]);
            assert_eq!(
                ready.config_fingerprint,
                Some(hex::encode(handshake.config.native_config_fingerprint))
            );
            assert_eq!(
                ready.protocol_version,
                iroha_data_model::sumeragi::PROTOCOL_VERSION
            );
            // Build- and configuration-bound values do not depend on the genesis.
            assert_eq!(ready.protocol_version, pending.protocol_version);
            assert_eq!(ready.wire_schema_hash, pending.wire_schema_hash);
            assert_eq!(ready.nexus_policy_digest, pending.nexus_policy_digest);
            assert_eq!(ready.gas_schedule_hash, pending.gas_schedule_hash);
        }

        #[test]
        fn check_config_node_identity_binds_resolved_local_settings_and_retired_keys() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let fixture = offline_semantic_genesis_fixture([]);
            let bootstrap = validate_genesis_execution_offline(
                &fixture.config,
                &fixture.genesis,
                &fixture.authority,
                fixture.mode,
                fixture.parameters,
                fixture.cadence_ms,
                None,
            )
            .expect("signed genesis executes offline");
            let report = |config: &Config| {
                compatibility_probe::config_compatibility_v1(
                    config,
                    Some((&fixture.genesis, &bootstrap)),
                    test_build_metadata(),
                )
                .expect("native configuration projection")
            };
            let baseline = report(&fixture.config);
            let identity = baseline
                .node_identity
                .as_ref()
                .expect("executed genesis identity");
            assert_eq!(bootstrap.initial_committee_size, 4);
            assert_eq!(identity.initial_committee_size, 4);
            assert_eq!(identity.network_id, bootstrap.network_id);
            assert_eq!(
                identity.node_id,
                PeerId::new(fixture.config.common.key_pair.public_key().clone())
            );
            use norito::codec::Encode as _;
            assert_eq!(
                identity.node_fingerprint,
                hex::encode(Hash::new(identity.node_id.encode()).as_ref())
            );
            assert_eq!(
                identity.node_config_fingerprint,
                hex::encode(
                    iroha_core::sumeragi::node::configuration_fingerprint(
                        bootstrap.initial_committee_size,
                        &fixture.config.sumeragi.local,
                        &iroha_core::sumeragi::driver::DriverConfig::default(),
                        &fixture.config.sumeragi.retired_keys,
                    )
                    .as_ref(),
                )
            );
            let mut changed = fixture.config.clone();
            changed.sumeragi.local.sync_batch = Some(17);
            let local = report(&changed);
            assert_ne!(
                local
                    .node_identity
                    .as_ref()
                    .unwrap()
                    .node_config_fingerprint,
                identity.node_config_fingerprint
            );
            assert_eq!(local.config_fingerprint, baseline.config_fingerprint);
            assert_eq!(local.diagnostic_build, baseline.diagnostic_build);
            changed = fixture.config.clone();
            changed.sumeragi.retired_keys = [0x61, 0x62]
                .into_iter()
                .map(|seed| {
                    KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                        .expect("deterministic retired key")
                        .public_key()
                        .clone()
                })
                .collect();
            let retired = report(&changed);
            assert_ne!(
                retired
                    .node_identity
                    .as_ref()
                    .unwrap()
                    .node_config_fingerprint,
                identity.node_config_fingerprint
            );
            changed.sumeragi.retired_keys.reverse();
            assert_eq!(report(&changed).node_identity, retired.node_identity);
            changed = fixture.config.clone();
            changed.sumeragi.records_dir = "unconsumed-diagnostic-records".into();
            changed.sumeragi.installation_log = "unconsumed-diagnostic-installation".into();
            assert_eq!(report(&changed).node_identity, baseline.node_identity);
        }

        #[test]
        fn check_config_node_identity_separates_diagnostic_build_from_running_identity() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let fixture = offline_semantic_genesis_fixture([]);
            let bootstrap = validate_genesis_execution_offline(
                &fixture.config,
                &fixture.genesis,
                &fixture.authority,
                fixture.mode,
                fixture.parameters,
                fixture.cadence_ms,
                None,
            )
            .expect("signed genesis executes offline");
            let build = |source| {
                CompiledBuildMetadata::from_compiled_parts(
                    env!("CARGO_PKG_VERSION"),
                    Some(source),
                    None,
                    None,
                    Some("test-diagnostic-features"),
                    Some("test-diagnostic-target"),
                )
            };
            let first = compatibility_probe::config_compatibility_v1(
                &fixture.config,
                Some((&fixture.genesis, &bootstrap)),
                build("2222222222222222222222222222222222222222"),
            )
            .expect("first diagnostic identity");
            let second = compatibility_probe::config_compatibility_v1(
                &fixture.config,
                Some((&fixture.genesis, &bootstrap)),
                build("1111111111111111111111111111111111111111"),
            )
            .expect("second diagnostic identity");
            assert_eq!(first.node_identity, second.node_identity);
            assert_eq!(first.config_fingerprint, second.config_fingerprint);
            assert_ne!(
                first.diagnostic_build.build_fingerprint,
                second.diagnostic_build.build_fingerprint
            );
            assert_eq!(
                first.diagnostic_build.source_revision,
                "2222222222222222222222222222222222222222"
            );
            assert_eq!(
                second.diagnostic_build.source_revision,
                "1111111111111111111111111111111111111111"
            );
            assert!(
                compatibility_probe::config_compatibility_v1(
                    &fixture.config,
                    Some((&fixture.genesis, &bootstrap)),
                    build("invalid-source"),
                )
                .is_err()
            );
            let pending = compatibility_probe::config_compatibility_v1(
                &fixture.config,
                None,
                build("1111111111111111111111111111111111111111"),
            )
            .expect("pending report has only the diagnostic build identity");
            assert_eq!(pending.node_identity, None);
            assert_eq!(pending.diagnostic_build, second.diagnostic_build);
        }

        #[test]
        fn check_config_offline_accepts_final_inrou_deployment_capability() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let genesis_authority = AccountId::new(
                KeyPair::try_from_seed(
                    b"offline-genesis-validation-authority".to_vec(),
                    Algorithm::Ed25519,
                )
                .unwrap()
                .public_key()
                .clone(),
            );
            let deployment_authority = AccountId::new(
                KeyPair::try_from_seed(vec![0x6A; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
            );
            let permission = Permission::new("CanManageSoracloud".into(), Json::new(()));
            let register: InstructionBox =
                Register::account(Account::new(deployment_authority.clone())).into();
            let cases: Vec<(&str, AccountId, Vec<InstructionBox>)> = vec![
                (
                    "existing genesis account",
                    genesis_authority.clone(),
                    vec![Grant::account_permission(permission.clone(), genesis_authority).into()],
                ),
                (
                    "dedicated direct grant",
                    deployment_authority.clone(),
                    vec![
                        register.clone(),
                        Grant::account_permission(permission.clone(), deployment_authority.clone())
                            .into(),
                    ],
                ),
                (
                    "live assigned role",
                    deployment_authority.clone(),
                    vec![
                        register,
                        Register::role(
                            Role::new(
                                "offline_inrou_deployer".parse().unwrap(),
                                deployment_authority,
                            )
                            .add_permission(permission),
                        )
                        .into(),
                    ],
                ),
            ];
            for (label, authority, instructions) in cases {
                let fixture = offline_semantic_genesis_fixture(instructions);
                validate_genesis_execution_offline(
                    &fixture.config,
                    &fixture.genesis,
                    &fixture.authority,
                    fixture.mode,
                    fixture.parameters,
                    fixture.cadence_ms,
                    Some(&authority),
                )
                .unwrap_or_else(|error| panic!("{label} must qualify: {error:?}"));
            }
        }
        #[test]
        fn check_config_offline_rejects_absent_or_revoked_inrou_deployment_capability() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let authority = AccountId::new(
                KeyPair::try_from_seed(vec![0x6A; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
            );
            let permission = Permission::new("CanManageSoracloud".into(), Json::new(()));
            let register: InstructionBox =
                Register::account(Account::new(authority.clone())).into();
            let grant: InstructionBox =
                Grant::account_permission(permission.clone(), authority.clone()).into();
            let role_id: RoleId = "offline_inrou_deployer".parse().unwrap();
            let role: InstructionBox = Register::role(
                Role::new(role_id.clone(), authority.clone()).add_permission(permission.clone()),
            )
            .into();
            let cases: Vec<(&str, Vec<InstructionBox>)> = vec![
                ("missing account", vec![]),
                ("missing permission", vec![register.clone()]),
                (
                    "direct grant then revoke",
                    vec![
                        register.clone(),
                        grant,
                        Revoke::account_permission(permission.clone(), authority.clone()).into(),
                    ],
                ),
                (
                    "revoked role membership",
                    vec![
                        register.clone(),
                        role.clone(),
                        Revoke::account_role(role_id.clone(), authority.clone()).into(),
                    ],
                ),
                (
                    "deleted role",
                    vec![
                        register.clone(),
                        role.clone(),
                        Unregister::role(role_id.clone()).into(),
                    ],
                ),
                (
                    "revoked role permission",
                    vec![
                        register,
                        role,
                        Revoke::role_permission(permission, role_id).into(),
                    ],
                ),
            ];
            for (label, instructions) in cases {
                let fixture = offline_semantic_genesis_fixture(instructions);
                let error = validate_genesis_execution_offline(
                    &fixture.config,
                    &fixture.genesis,
                    &fixture.authority,
                    fixture.mode,
                    fixture.parameters,
                    fixture.cadence_ms,
                    Some(&authority),
                )
                .err()
                .unwrap_or_else(|| panic!("{label} must fail final-state qualification"));
                assert!(
                    format!("{error:?}")
                        .contains("lacks exact CanManageSoracloud in final genesis state"),
                    "{label} must execute successfully before failing the final capability check: {error:?}",
                );
            }
        }
        #[test]
        fn check_config_offline_rejects_malformed_inrou_management_grants() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let authority = AccountId::new(
                KeyPair::try_from_seed(vec![0x6A; 32], Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
            );
            let malformed = Permission::new("CanManageSoracloud".into(), Json::new(false));
            let grants: [InstructionBox; 2] = [
                Grant::account_permission(malformed.clone(), authority.clone()).into(),
                Register::role(
                    Role::new("offline_inrou_deployer".parse().unwrap(), authority.clone())
                        .add_permission(malformed),
                )
                .into(),
            ];
            for grant in grants {
                let fixture = offline_semantic_genesis_fixture([
                    Register::account(Account::new(authority.clone())).into(),
                    grant,
                ]);
                let error = validate_genesis_execution_offline(
                    &fixture.config,
                    &fixture.genesis,
                    &fixture.authority,
                    fixture.mode,
                    fixture.parameters,
                    fixture.cadence_ms,
                    Some(&authority),
                )
                .err()
                .expect("same-named malformed token must never qualify");
                let startup = error
                    .downcast_ref::<iroha_core::sumeragi::startup::StartupError>()
                    .expect("offline failure retains the native startup error");
                assert!(matches!(
                    startup,
                    iroha_core::sumeragi::startup::StartupError::InvalidGenesis(error)
                        if matches!(error.as_ref(), iroha_core::block::BlockValidationError::InvalidGenesis(
                            iroha_core::block::InvalidGenesisError::RejectedOutput(_)
                        ))
                ));
            }
        }
        #[test]
        fn check_config_inrou_authority_requires_canonical_account_and_signed_genesis() {
            let config = sample_config();
            let _discriminant = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
                *config.common.chain_discriminant.value(),
            );
            let account = AccountId::new(config.genesis.public_key.clone()).to_string();
            let error = validate_config_and_genesis_for_check(&config, None, Some(&account))
                .map(drop)
                .expect_err("an unavailable genesis cannot satisfy deployment qualification");
            assert!(
                format!("{error:?}").contains("cannot be qualified without the signed genesis")
            );
            for invalid in [
                "not-an-account".to_owned(),
                format!(" {account}"),
                format!("{account}@domain"),
            ] {
                let error = validate_config_and_genesis_for_check(&config, None, Some(&invalid))
                    .map(drop)
                    .expect_err(
                        "the authority must use the configured chain's canonical account encoding",
                    );
                assert!(
                    format!("{error:?}")
                        .contains("must be a canonical account ID for the configured chain")
                );
            }
        }
        #[test]
        fn check_config_accepts_taira_without_offline_backend_settings() {
            let mut config = sample_config();
            config.common.chain = ChainId::from("taira");
            config.confidential.enabled = true;
            config.confidential.assume_valid = false;
            validate_config_and_genesis_for_check(&config, None, None)
                .map(drop)
                .expect("Taira has universal offline primitives without backend enablement");
        }
        #[test]
        fn check_config_qualifies_the_fixed_moderation_strict_ingress() {
            let mut exact = sample_config();
            configure_exact_moderation_strict_ingress(&mut exact);
            assert!(
                validate_config_and_genesis_for_check(&exact, None, None)
                    .map(drop)
                    .is_ok()
            );
            for (mutation, expected) in [
                (0, "runtime-provider binding is substituted"),
                (1, "runtime-provider binding is stale or revoked"),
            ] {
                let mut invalid = exact.clone();
                let moderation = invalid
                    .torii
                    .sorafs_storage
                    .moderation_orchestrator
                    .as_mut()
                    .expect("configured moderation runtime");
                if mutation == 0 {
                    moderation.strict_ingress_handle =
                        "torii.sorafs.moderation-strict-ingress.secondary".into();
                } else {
                    moderation.strict_ingress_revision += 1;
                }
                let report = validate_config_and_genesis_for_check(&invalid, None, None)
                    .map(drop)
                    .expect_err("invalid fixed ingress binding must fail check-config");
                assert!(format!("{report:#}").contains(expected));
            }
        }
        #[test]
        fn check_config_offline_rejects_genesis_instruction_failure() {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let duplicate_domain =
                iroha_model_base::domain::DomainId::try_new("duplicate", "universal")
                    .expect("valid domain id");
            let instructions = [
                Register::domain(Domain::new(duplicate_domain.clone())).into(),
                Register::domain(Domain::new(duplicate_domain)).into(),
            ];
            let fixture = offline_semantic_genesis_fixture(instructions);
            let error = validate_genesis_execution_offline(
                &fixture.config,
                &fixture.genesis,
                &fixture.authority,
                fixture.mode,
                fixture.parameters,
                fixture.cadence_ms,
                None,
            )
            .err()
            .expect("duplicate genesis registration must fail semantic execution");
            let startup = error
                .downcast_ref::<iroha_core::sumeragi::startup::StartupError>()
                .expect("offline failure retains the native startup error");
            let iroha_core::sumeragi::startup::StartupError::InvalidGenesis(error) = startup else {
                panic!("unexpected offline validation error: {startup:?}");
            };
            let iroha_core::block::BlockValidationError::InvalidGenesis(
                iroha_core::block::InvalidGenesisError::RejectedOutput(rejection),
            ) = error.as_ref()
            else {
                panic!("unexpected native validation error: {error:?}");
            };
            assert!(matches!(
                rejection.reason.as_ref(),
                iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                    iroha_data_model::ValidationFail::InstructionFailed(
                        iroha_data_model::isi::error::InstructionExecutionError::Repetition(_)
                    )
                )
            ));
        }
        #[test]
        fn consensus_config_caps_use_canonical_fields() {
            let config = sample_config();
            let caps = build_consensus_config_caps(&config.nexus, None, None)
                .expect("config caps should build");
            let expected_nexus_policy_digest = iroha_config::parameters::actual::nexus_consensus_policy_digest_with_runtime_policies(
                &config.nexus,
                None,
                None,
            )
            .expect("default Nexus config should produce a policy digest");
            assert_eq!(caps.native_config_fingerprint, [0; 32]);
            assert_eq!(caps.nexus_policy_digest, expected_nexus_policy_digest);
            assert_eq!(
                caps.ivm_gas_schedule_hash,
                <[u8; 32]>::from(ivm::gas::schedule_hash())
            );
        }
        #[test]
        fn verify_genesis_metadata_rejects_consensus_mode_mismatch() -> eyre::Result<()> {
            use iroha_data_model::parameter::system::SumeragiConsensusMode;
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let config = sample_config();
            let genesis_keys = config.common.key_pair.clone();
            let chain = config.common.chain.clone();
            let permissioned_genesis = complete_test_genesis_builder(
                GenesisBuilder::new_without_executor(chain.clone(), PathBuf::from(".")),
            )
            .build_raw()
            .expect("build complete permissioned genesis manifest")
            .with_consensus_meta()?
            .build_and_sign(&genesis_keys)?;
            let npos_genesis = complete_test_genesis_builder(
                GenesisBuilder::new_without_executor(chain.clone(), PathBuf::from("."))
                    .append_parameter(Parameter::Custom(
                        iroha_data_model::parameter::system::SumeragiNposParameters::default()
                            .into_custom_parameter(),
                    )),
            )
            .build_raw()
            .expect("build complete NPoS genesis manifest")
            .with_consensus_mode(SumeragiConsensusMode::Npos)
            .with_consensus_meta()?
            .build_and_sign(&genesis_keys)?;
            let config_caps = build_consensus_config_caps(&config.nexus, None, None)
                .map_err(|err| eyre::eyre!(format!("{err:?}")))?;
            let (mode_tag, _bls_domain, consensus_caps, _, _) =
                consensus_caps_from_genesis(&permissioned_genesis, &config_caps)
                    .expect("permissioned signed genesis must produce canonical consensus caps");
            let proto = iroha_core::sumeragi::consensus::PROTO_VERSION;
            let err =
                verify_genesis_metadata(&npos_genesis, &config, &consensus_caps, &mode_tag, proto)
                    .expect_err("signed genesis mode mismatch should be detected");
            assert!(
                format!("{err:?}").contains("consensus_mode"),
                "error should mention consensus_mode mismatch: {err:?}"
            );
            Ok(())
        }
        #[test]
        fn verify_genesis_metadata_rejects_fingerprint_mismatch() -> eyre::Result<()> {
            let _registry_guard = instruction_registry_test_guard();
            iroha_genesis::init_instruction_registry();
            let config = sample_config();
            let genesis_keys = config.common.key_pair.clone();
            let chain = config.common.chain.clone();
            let genesis_block = complete_test_genesis_builder(
                GenesisBuilder::new_without_executor(chain, PathBuf::from(".")),
            )
            .build_raw()
            .expect("build complete fingerprint-mismatch genesis manifest")
            .with_consensus_meta()?
            .build_and_sign(&genesis_keys)?;
            let config_caps = build_consensus_config_caps(&config.nexus, None, None)
                .map_err(|err| eyre::eyre!(format!("{err:?}")))?;
            let (mode_tag, _bls_domain, mut consensus_caps, _, _) =
                consensus_caps_from_genesis(&genesis_block, &config_caps)
                    .expect("signed genesis must produce canonical consensus caps");
            // Raw manifest fingerprints are normalized during signing. Mutate
            // the expected admission fingerprint after deriving it from the
            // actual signed genesis so this exercises the mismatch gate.
            consensus_caps.consensus_fingerprint[0] ^= 1;
            let proto = iroha_core::sumeragi::consensus::PROTO_VERSION;
            let err =
                verify_genesis_metadata(&genesis_block, &config, &consensus_caps, &mode_tag, proto)
                    .expect_err("tampered fingerprint should be rejected");
            assert!(
                format!("{err:?}")
                    .to_ascii_lowercase()
                    .contains("fingerprint"),
                "expected fingerprint mismatch error, got {err:?}"
            );
            Ok(())
        }
        #[cfg(feature = "sm")]
        #[test]
        fn manifest_crypto_cannot_override_config_without_signed_genesis() -> eyre::Result<()> {
            let genesis_keys = KeyPair::random();
            let mut config_table = sample_config_table();
            iroha_config::base::toml::Writer::new(&mut config_table)
                .write(
                    ["genesis", "public_key"],
                    genesis_keys.public_key().to_string(),
                )
                .write(["kura", "store_dir"], "./storage")
                .write(["snapshot", "store_dir"], "./snapshots")
                .write(["dev_telemetry", "out_file"], "./telemetry.log");
            if let Some(genesis_table) = config_table
                .get_mut("genesis")
                .and_then(toml::Value::as_table_mut)
            {
                genesis_table.remove("file");
            }
            let mut manifest_crypto = ManifestCrypto::default();
            manifest_crypto.default_hash = "sm3-256".to_owned();
            manifest_crypto.allowed_signing = vec![Algorithm::Ed25519, Algorithm::Sm2];
            manifest_crypto.allowed_curve_ids =
                iroha_config::parameters::defaults::crypto::derive_curve_ids_from_algorithms(
                    &manifest_crypto.allowed_signing,
                );
            manifest_crypto.sm2_distid_default = "CN1234567812345678".to_owned();
            manifest_crypto.validate()?;
            let manifest = complete_test_genesis_builder(
                GenesisBuilder::new_without_executor(
                    ChainId::from("test-chain"),
                    PathBuf::from("."),
                )
                .with_crypto(manifest_crypto),
            )
            .build_raw()
            .expect("build complete SM manifest crypto fixture");
            let temp_dir = tempfile::tempdir()?;
            let config_path = temp_dir.path().join("config.toml");
            let manifest_path = temp_dir.path().join("manifest.json");
            std::fs::write(&config_path, toml::to_string(&config_table)?)?;
            std::fs::write(&manifest_path, norito::json::to_vec(&manifest)?)?;
            let (config, genesis) = read_config_and_genesis(&Args {
                config: Some(config_path),
                genesis_manifest_json: Some(manifest_path),
                startup: StartupArgs {
                    check_config: false,
                    json: false,
                    check_storage: false,
                    require_genesis_inrou_deployment_authority: None,
                    trace_config: false,
                    config_blake3: None,
                    sumeragi_assert_fresh_key: false,
                },
                terminal_colors: false,
                language: None,
                sora: false,
                #[cfg(feature = "test-network-parliament-signers")]
                test_network_parliament_beacon_signer_mode:
                    TestNetworkParliamentBeaconSignerMode::Valid,
                fastpq_execution_mode: None,
                fastpq_poseidon_mode: None,
                fastpq_device_class: None,
                fastpq_chip_family: None,
                fastpq_gpu_kind: None,
            })
            .map_err(|report| eyre::eyre!("{report:?}"))?;
            assert!(genesis.is_none());
            // An unsigned manifest is a consistency input, not an alternate
            // authority for node crypto parameters before signed genesis.
            assert!(
                config
                    .crypto
                    .default_hash
                    .eq_ignore_ascii_case("blake2b-256")
            );
            assert!(!config.crypto.allowed_signing.contains(&Algorithm::Sm2));
            assert_ne!(config.crypto.sm2_distid_default, "CN1234567812345678");
            let selected_manifest = config
                .genesis
                .manifest_json
                .as_ref()
                .expect("CLI manifest remains selected")
                .resolve_relative_path();
            let retained_manifest = read_genesis_manifest(&selected_manifest)
                .map_err(|error| eyre::eyre!("{error:?}"))?;
            assert!(
                retained_manifest
                    .crypto()
                    .default_hash
                    .eq_ignore_ascii_case("sm3-256")
            );
            assert!(
                ensure_manifest_crypto_matches(&retained_manifest, &config)
                    .expect_err("unsigned crypto substitution must fail startup consistency")
                    .contains("crypto mismatch")
            );
            Ok(())
        }
    }
    mod config_integration {
        #[allow(unused_imports)]
        use super::*;
        use assertables::assert_contains;
        use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair, bls_normal_pop_prove};
        use iroha_genesis::GenesisBuilder;
        use iroha_model_base::chain::ChainId;
        use iroha_primitives::addr::socket_addr;

        fn config_test_args(config_path: PathBuf, genesis_manifest_json: Option<PathBuf>) -> Args {
            Args {
                config: Some(config_path),
                genesis_manifest_json,
                startup: StartupArgs {
                    check_config: false,
                    json: false,
                    check_storage: false,
                    require_genesis_inrou_deployment_authority: None,
                    trace_config: false,
                    config_blake3: None,
                    sumeragi_assert_fresh_key: false,
                },
                terminal_colors: false,
                language: None,
                sora: false,
                #[cfg(feature = "test-network-parliament-signers")]
                test_network_parliament_beacon_signer_mode:
                    TestNetworkParliamentBeaconSignerMode::Valid,
                fastpq_execution_mode: None,
                fastpq_poseidon_mode: None,
                fastpq_device_class: None,
                fastpq_chip_family: None,
                fastpq_gpu_kind: None,
            }
        }

        fn read_config_with_fixture_space(
            args: &Args,
        ) -> ReportResult<(Config, Option<GenesisBlock>), ConfigError> {
            // Explicit capacity-only fixture observation, not host disk qualification.
            read_config_and_genesis_with_filesystem_space(args, |_| {
                Some((32 * 1024 * 1024 * 1024, 64 * 1024 * 1024 * 1024))
            })
        }

        fn config_factory(genesis_public_key: &PublicKey) -> toml::Table {
            let keypair = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
            let pubkey = keypair.public_key().clone();
            let privkey = keypair.private_key().clone();
            let pop = bls_normal_pop_prove(&privkey).expect("pop prove");
            let mut table = toml::Table::new();
            iroha_config::base::toml::Writer::new(&mut table)
                .write("chain", "0")
                .write("public_key", pubkey.to_string())
                // Use `ExposedPrivateKey`'s Display impl to emit the actual hex instead of
                // the redacted placeholder provided by `PrivateKey::Display`.
                .write("private_key", ExposedPrivateKey(privkey).to_string())
                .write(
                    "soranet_transport_public_key",
                    "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B",
                )
                .write(
                    "soranet_transport_private_key",
                    "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89",
                )
                .write(
                    ["network", "address"],
                    socket_addr!(127.0.0.1:1337).to_literal(),
                )
                .write(
                    ["network", "public_address"],
                    socket_addr!(127.0.0.1:1337).to_literal(),
                )
                .write(
                    ["torii", "address"],
                    socket_addr!(127.0.0.1:8080).to_literal(),
                )
                .write(
                    ["streaming", "identity_public_key"],
                    "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB",
                )
                .write(
                    ["streaming", "identity_private_key"],
                    "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F",
                )
                .write(["confidential", "enabled"], true)
                .write(["confidential", "assume_valid"], false)
                .write(["genesis", "public_key"], genesis_public_key.to_string())
                .write(
                    ["genesis", "expected_hash"],
                    "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E",
                );
            let mut pop_entry = toml::Table::new();
            pop_entry.insert(
                "public_key".to_string(),
                toml::Value::String(pubkey.to_string()),
            );
            pop_entry.insert("pop_hex".to_string(), toml::Value::String(hex::encode(pop)));
            table.insert(
                "trusted_peers_pop".to_string(),
                toml::Value::Array(vec![toml::Value::Table(pop_entry)]),
            );
            table
        }
        fn load_config_with_overrides<F>(
            mut adjust: F,
        ) -> eyre::Result<(Config, tempfile::TempDir, PathBuf)>
        where
            F: FnMut(&mut toml::Table, &KeyPair),
        {
            let genesis_key_pair = KeyPair::random();
            let raw = complete_test_genesis_builder(GenesisBuilder::new_without_executor(
                ChainId::from("chain"),
                ".",
            ))
            .build_raw()
            .expect("build complete configuration fixture genesis manifest");
            iroha_genesis::init_instruction_registry();
            let proposal = raw
                .build_and_sign(&genesis_key_pair)
                .expect("build prepared genesis proposal");
            assert!(proposal.0.is_resultless_proposal());
            let mut config = config_factory(genesis_key_pair.public_key());
            iroha_config::base::toml::Writer::new(&mut config)
                .write(["genesis", "file"], "./genesis/genesis.proposal.nrt")
                .write(
                    ["genesis", "expected_hash"],
                    NetworkId::from_genesis_hash(proposal.0.hash()).to_string(),
                )
                .write(["kura", "store_dir"], "../storage")
                .write(["snapshot", "store_dir"], "../snapshots")
                .write(["dev_telemetry", "out_file"], "../logs/telemetry");
            adjust(&mut config, &genesis_key_pair);
            let dir = tempfile::tempdir()?;
            let config_dir = dir.path().join("config");
            let genesis_dir = config_dir.join("genesis");
            std::fs::create_dir_all(&genesis_dir)?;
            let config_path = config_dir.join("config.toml");
            let genesis_path = genesis_dir.join("genesis.proposal.nrt");
            let executor_path = genesis_dir.join("executor.to");
            std::fs::write(&config_path, toml::to_string(&config)?)?;
            std::fs::write(&genesis_path, proposal.0.encode_wire()?)?;
            std::fs::write(&executor_path, "")?;
            let (config, _genesis) =
                read_config_with_fixture_space(&config_test_args(config_path.clone(), None))
                    .map_err(|report| eyre::eyre!("{report:?}"))?;
            Ok((config, dir, config_path))
        }
        #[test]
        fn cli_genesis_manifest_path_overrides_config() -> eyre::Result<()> {
            let (_config, dir, config_path) = load_config_with_overrides(|table, _| {
                iroha_config::base::toml::Writer::new(table)
                    .write(["genesis", "manifest_json"], "./stale-manifest.json");
            })?;
            let manifest_path = dir.path().join("bound-genesis.json");
            std::fs::write(&manifest_path, b"{}")?;
            let (config, _genesis) = read_config_with_fixture_space(&config_test_args(
                config_path,
                Some(manifest_path.clone()),
            ))
            .map_err(|report| eyre::eyre!("{report:?}"))?;
            assert_eq!(
                config
                    .genesis
                    .manifest_json
                    .as_ref()
                    .expect("CLI manifest override should be retained")
                    .resolve_relative_path(),
                manifest_path
            );
            Ok(())
        }
        fn parse_config_with_overrides<F>(
            mut adjust: F,
        ) -> eyre::Result<(Config, tempfile::TempDir, PathBuf)>
        where
            F: FnMut(&mut toml::Table, &KeyPair),
        {
            let genesis_key_pair = KeyPair::random();
            let mut config = config_factory(genesis_key_pair.public_key());
            iroha_config::base::toml::Writer::new(&mut config)
                .write(["kura", "store_dir"], "../storage")
                .write(["snapshot", "store_dir"], "../snapshots")
                .write(["dev_telemetry", "out_file"], "../logs/telemetry");
            adjust(&mut config, &genesis_key_pair);
            let dir = tempfile::tempdir()?;
            let config_dir = dir.path().join("config");
            std::fs::create_dir_all(&config_dir)?;
            let config_path = config_dir.join("config.toml");
            std::fs::write(&config_path, toml::to_string(&config)?)?;
            let mut reader = ConfigReader::new();
            reader = reader
                .read_toml_with_extends(&config_path)
                .map_err(|report| eyre::eyre!("{report:?}"))?;
            let config = reader
                .read_and_complete::<UserConfig>()
                .map_err(|report| eyre::eyre!("{report:?}"))?
                .parse()
                .map_err(|report| eyre::eyre!("{report:?}"))?;
            Ok((config, dir, config_path))
        }
        fn storage_budget_probe(
            total_bytes: u64,
            available_bytes: u64,
            managed_bytes: u64,
        ) -> StorageBudgetFilesystemProbe {
            StorageBudgetFilesystemProbe {
                filesystem_id: "dev:test".to_owned(),
                path: PathBuf::from("/tmp/nexus-storage"),
                total_bytes,
                available_bytes,
                managed_bytes,
                components: vec![NexusStorageBudgetComponent::Kura],
                managed_roots: Vec::new(),
                derived_budget_bytes: None,
            }
        }
        #[test]
        fn runtime_derived_budget_does_not_mutate_operator_configuration() -> eyre::Result<()> {
            let (mut config, _dir, config_path) = parse_config_with_overrides(|_, _| {})?;
            let original_config = std::fs::read_to_string(&config_path)?;
            assert!(config.nexus.storage.local_budget_bytes.is_none());
            assert!(config.nexus.storage.effective_local_budget_bytes.is_none());
            let filesystem_budget = NexusStorageFilesystemBudget {
                budget_bytes: NonZeroU64::new(800).expect("non-zero budget"),
                components: vec![NexusStorageBudgetComponent::Kura],
            };
            let aggregate = config
                .apply_derived_storage_budget(&[filesystem_budget])
                .expect("valid filesystem budget");
            assert_eq!(aggregate.get(), 800);
            assert!(config.nexus.storage.local_budget_bytes.is_none());
            assert_eq!(
                config
                    .nexus
                    .storage
                    .effective_local_budget_bytes
                    .map(iroha_config::base::util::Bytes::get),
                Some(800)
            );
            assert_eq!(config.kura.max_disk_usage_bytes.get(), 800);
            assert_eq!(std::fs::read_to_string(config_path)?, original_config);
            Ok(())
        }
        #[test]
        fn operator_local_budget_initializes_the_effective_budget() -> eyre::Result<()> {
            let (config, _dir, config_path) =
                parse_config_with_overrides(|table, _genesis_key| {
                    iroha_config::base::toml::Writer::new(table)
                        .write(["nexus", "storage", "local_budget_bytes"], 4_096_i64);
                })?;
            assert_eq!(
                config
                    .nexus
                    .storage
                    .local_budget_bytes
                    .map(iroha_config::base::util::Bytes::get),
                Some(4_096)
            );
            assert_eq!(
                config
                    .nexus
                    .storage
                    .effective_local_budget_bytes
                    .map(iroha_config::base::util::Bytes::get),
                Some(4_096)
            );
            let persisted: toml::Value = toml::from_str(&std::fs::read_to_string(config_path)?)?;
            let storage = persisted
                .get("nexus")
                .and_then(toml::Value::as_table)
                .and_then(|nexus| nexus.get("storage"))
                .and_then(toml::Value::as_table)
                .expect("storage table");
            assert_eq!(
                storage
                    .get("local_budget_bytes")
                    .and_then(toml::Value::as_integer),
                Some(4_096)
            );
            assert!(storage.get("effective_local_budget_bytes").is_none());
            assert!(storage.get("auto_default").is_none());
            assert!(storage.get("max_disk_usage_bytes").is_none());
            Ok(())
        }
        #[test]
        fn runtime_budget_uses_checked_capacity_minus_ceil_headroom() {
            let probe = storage_budget_probe(1_001, 301, 0);
            let budgets =
                derive_runtime_nexus_storage_budget(&[probe]).expect("safe derived budget");
            assert_eq!(budgets.len(), 1);
            assert_eq!(budgets[0].budget_bytes.get(), 100);
        }
        #[test]
        fn runtime_budget_is_stable_across_restart_usage_splits() {
            let before_restart = storage_budget_probe(1_000, 700, 100);
            let after_restart = storage_budget_probe(1_000, 300, 500);
            let before = derive_runtime_nexus_storage_budget(&[before_restart])
                .expect("safe pre-restart budget");
            let after = derive_runtime_nexus_storage_budget(&[after_restart])
                .expect("safe post-restart budget");
            assert_eq!(before[0].budget_bytes, after[0].budget_bytes);
            assert_eq!(before[0].budget_bytes.get(), 600);
        }
        #[test]
        fn runtime_budget_rejects_existing_usage_above_the_safe_cap() {
            let probe = storage_budget_probe(1_000, 100, 150);
            let error = derive_runtime_nexus_storage_budget(&[probe])
                .expect_err("auto derivation must not activate a cap below managed usage");
            let diagnostic = format!("{error:?}");
            assert!(
                diagnostic.contains("below the 150 managed bytes"),
                "{diagnostic}"
            );
        }
        #[cfg(unix)]
        include!("main/runtime_budget_and_config_tests.rs");
    }
    include!("main/startup_tail_tests.rs");
}
/// Result type returned by daemon launcher and startup operations.
pub type ReportResult<T, E> = core::result::Result<T, Report<E>>;

fn preflight_empty_state_snapshot_fallback(
    kura: &Kura,
    network_id: &NetworkId,
    configured_lane_catalog: &iroha_data_model::nexus::LaneCatalog,
) -> ReportResult<(), StartError> {
    State::preflight_configured_primary_geometry_replay(
        kura,
        network_id,
        configured_lane_catalog,
    )
    .map_err(|error| Report::new(error).change_context(StartError::InitKura))
    .map_err(|report| {
        report.attach(
            "cannot rebuild from an empty state because retained Kura geometry no longer reaches the configured-primary replay floor",
        )
    })
}

fn authenticated_maximum_validator_roster_len(
    mode: iroha_data_model::block::consensus::ConsensusMode,
    permissioned_roster_len: usize,
    npos_max_validators: Option<u32>,
) -> Result<usize, String> {
    match mode {
        iroha_data_model::block::consensus::ConsensusMode::Permissioned => {
            if !iroha_data_model::block::consensus::is_valid_committee_size(permissioned_roster_len)
            {
                return Err(
                    "authenticated permissioned roster is not a bounded 3f + 1 committee"
                        .to_owned(),
                );
            }
            Ok(permissioned_roster_len)
        }
        iroha_data_model::block::consensus::ConsensusMode::Npos => {
            let maximum = npos_max_validators.ok_or_else(|| {
                "authenticated NPoS state is missing signed election parameters".to_owned()
            })?;
            let maximum = usize::try_from(maximum).map_err(|_| {
                "authenticated NPoS maximum validator roster does not fit this platform".to_owned()
            })?;
            if !iroha_data_model::block::consensus::is_valid_committee_size(maximum) {
                return Err(
                    "authenticated NPoS maximum validator roster is not a bounded 3f + 1 committee"
                        .to_owned(),
                );
            }
            Ok(maximum)
        }
    }
}

#[cfg(test)]
mod authenticated_roster_capacity_tests {
    use super::authenticated_maximum_validator_roster_len;
    use iroha_data_model::block::consensus::ConsensusMode;

    #[test]
    fn native_roster_capacity_requires_the_bounded_signed_committee() {
        for size in 0..=33 {
            let valid = (4..=31).contains(&size) && size % 3 == 1;
            let permissioned =
                authenticated_maximum_validator_roster_len(ConsensusMode::Permissioned, size, None);
            let npos = authenticated_maximum_validator_roster_len(
                ConsensusMode::Npos,
                4,
                Some(size as u32),
            );
            assert_eq!(permissioned.is_ok(), valid, "permissioned {size}");
            assert_eq!(npos.is_ok(), valid, "NPoS {size}");
            if valid {
                assert_eq!(permissioned.unwrap(), size);
                assert_eq!(npos.unwrap(), size);
            }
        }
        assert!(authenticated_maximum_validator_roster_len(ConsensusMode::Npos, 4, None).is_err());
    }
}

#[cfg(test)]
mod sora_profile_geometry_tests;
