//! Puppeteer for `irohad`, to create test networks
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
mod config;
mod dedicated_read;
#[cfg(unix)]
mod disposable_runtime_provider_broker;
mod private_settlement_route_control;
#[cfg(unix)]
pub use disposable_runtime_provider_broker::{
    DisposableBeaconProviderBinding, new_disposable_owner_private_root,
};
#[cfg(unix)]
mod disposable_rotation_ceremony;
#[cfg(unix)]
pub use disposable_rotation_ceremony::{
    DisposableGenesisConfigSeat, DisposableGenesisDkgOutput, DisposablePendingCustodyInput,
    DisposablePreparedBeaconCustody, DisposableRetainedBeaconCredential,
    DisposableRotationDkgOutput, DisposableRotationProofInput, DisposableRotationSeatOutput,
    prepare_disposable_pending_custody, run_disposable_genesis_dkg,
    run_disposable_genesis_dkg_from_configs, run_disposable_rotation_dkg,
};
pub mod fslock_ports;
pub mod genesis_support;
use color_eyre::eyre::{Context, Report, Result, eyre};
pub use config::chain_id;
pub use config::genesis_participant_committee_key_instructions;
use core::{fmt, future::Future, time::Duration};
pub use dedicated_read::read_on_dedicated_thread;
use fslock::LockFile;
use fslock_ports::AllocatedPort;
use futures::{prelude::*, stream::FuturesUnordered};
use iroha::data_model::block::consensus::{
    MAX_VALIDATORS_PER_HEIGHT, MIN_VALIDATORS_PER_HEIGHT, is_valid_committee_size,
};
use iroha::data_model::sumeragi::SumeragiStatus;
use iroha::{blocking::Client, client::Client as AsyncClient, data_model::prelude::*};
use iroha_config::base::{
    ParameterOrigin,
    env::MockEnv,
    read::ConfigReader,
    toml::{TomlSource, WriteExt as _, Writer as TomlWriter},
};
use iroha_core::sumeragi::{
    consensus::{
        NPOS_TAG, PERMISSIONED_TAG, PROTO_VERSION, compute_consensus_parameters_fingerprint,
    },
    startup::genesis_committee_peers,
};
use iroha_crypto::{
    Algorithm, ExposedPrivateKey, Hash as CryptoHash, KeyPair, PrivateKey, PublicKey, sha256,
    sha256_reader_bounded,
};
use iroha_data_model::da::commitment::DaProofPolicyBundle;
use iroha_data_model::{
    account::AccountId,
    alias_setup::{
        AccountAliasName, AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1,
        AliasDataSpaceIntentV1, AliasDomainIntentV1, AliasIntentV1, AliasLeaseAcquisitionV1,
        AliasQuoteGuardV1, ResolvedAccountAliasV1, ResolvedDataSpaceV1, ResolvedDomainV1,
    },
    block::consensus::{ConsensusGenesisModeParams, ConsensusGenesisParams},
    domain::NewDomain,
    isi::{
        InstructionBox, SetParameter,
        alias_setup::EnsureAlias,
        register::RegisterBox,
        set_instruction_registry,
        staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
    },
    parameter::{
        CustomParameter, SmartContractParameter,
        system::{
            ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode,
            SumeragiNposParameters, consensus_metadata,
        },
    },
    sns::NameStatus,
    transaction::Executable,
};
use iroha_genesis::{GenesisBlock, GenesisTopologyEntry, RawGenesisTransaction};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::DataSpaceId;
use iroha_model_base::topology::LaneId;
use iroha_primitives::{
    addr::{SocketAddr, socket_addr},
    json::Json,
    unique_vec::UniqueVec,
};
use iroha_test_samples::{
    ALICE_ID, ALICE_KEYPAIR, BOB_ID, CARPENTER_ID, PEER_KEYPAIR, REAL_GENESIS_ACCOUNT_KEYPAIR,
    SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
};
use iroha_torii_shared::status::Status;
use iroha_version::codec::EncodeVersioned;
use nonzero_ext::nonzero;
use norito::json::{self, Value as JsonValue};
pub use private_settlement_route_control::{
    PrivateSettlementRouteControl, PrivateSettlementRouteControlAck,
    PrivateSettlementRouteControlAction, PrivateSettlementRouteControlCommand,
    PrivateSettlementRouteControlPhase,
};
use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet, hash_map::DefaultHasher},
    ffi::OsString,
    fs,
    hash::{Hash as StdHash, Hasher},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    iter,
    net::TcpListener,
    num::NonZero,
    ops::Deref,
    path::{Component, Path, PathBuf},
    process::{ExitStatus, Output, Stdio},
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
// no external dependency needed: versioned encoding is a single leading byte (1)
use crate::config::ensure_genesis_results_with_runtime_config;
/// Consensus mode frozen into the test network's signed genesis profile.
pub use iroha_data_model::block::consensus::ConsensusMode;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener as TokioTcpListener, TcpStream},
    process::Child,
    runtime::{self, Runtime},
    sync::{Mutex, Notify, OwnedRwLockWriteGuard, RwLock, broadcast, oneshot, watch},
    task::{JoinHandle, JoinSet, spawn_blocking},
    time::timeout,
};
use toml::{Table, Value, map::Entry};
use tracing::{Instrument, debug, error, info, info_span, warn};
const TEST_SNS_LEASE_PAYMENT: &str = "0.5";
const TEST_SNS_POLICY_VERSION: u16 = 1;
const TEST_SNS_PAYMENT_ASSET_DEFINITION: &str = "61CtjvNd9T3THAR65GsMVHr82Bjc";
const TEST_SNS_LEASE_VISIBILITY_TIMEOUT: Duration = Duration::from_secs(120);
const TEST_SNS_LEASE_VISIBILITY_POLL: Duration = Duration::from_millis(250);
fn checked_key_pair_from_seed(seed: impl Into<Vec<u8>>, algorithm: Algorithm) -> KeyPair {
    KeyPair::try_from_seed(seed.into(), algorithm)
        .expect("fixture seed must derive a valid keypair")
}
const P2P_SORANET_TRANSPORT_SEED_DOMAIN: &[u8] = b":p2p-soranet-transport";
fn checked_soranet_transport_key_pair_from_seed(mut seed: Vec<u8>) -> KeyPair {
    seed.extend_from_slice(P2P_SORANET_TRANSPORT_SEED_DOMAIN);
    checked_key_pair_from_seed(seed, Algorithm::Ed25519)
}
fn random_soranet_transport_key_pair_distinct_from(streaming: &KeyPair) -> KeyPair {
    loop {
        let candidate = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate checked random SoraNet transport keypair");
        if candidate.public_key() != streaming.public_key() {
            return candidate;
        }
    }
}
pub use crate::config::genesis as genesis_factory;

/// Build a signed custom genesis with post-topology instructions and defer
/// transaction execution to [`NetworkBuilder`].
///
/// Use this only as the return value of [`NetworkBuilder::with_genesis_block`]
/// or [`NetworkBuilder::with_genesis_block_and_observers`] when the instructions
/// require the builder's final pipeline, Nexus, or ZK configuration. The builder
/// normalizes and pre-executes the block under that fully merged configuration
/// before publishing identical prepared bytes to every peer. The returned block
/// is not prepared genesis on its own.
pub fn unexecuted_genesis_factory_with_post_topology(
    extra_transactions: Vec<Vec<InstructionBox>>,
    post_topology_transactions: Vec<Vec<InstructionBox>>,
    topology: UniqueVec<PeerId>,
    topology_entries: Vec<GenesisTopologyEntry>,
) -> GenesisBlock {
    crate::config::genesis_unexecuted_with_keypair_and_post_topology(
        extra_transactions,
        post_topology_transactions,
        topology,
        topology_entries,
        SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
    )
}

fn test_domain_dataspace_id(domain: &DomainId) -> Result<DataSpaceId> {
    iroha_core::sns::dataspace_id_for_sns_alias(domain.dataspace().as_ref()).ok_or_else(|| {
        eyre!(
            "derive deterministic dataspace id for domain `{domain}`; pass an explicit id for a static catalog mapping"
        )
    })
}
fn test_domain_setup_instruction(
    domain: &DomainId,
    dataspace_id: DataSpaceId,
    owner: &AccountId,
) -> Result<EnsureAlias> {
    let payment_asset = AssetDefinitionId::parse_address_literal(TEST_SNS_PAYMENT_ASSET_DEFINITION)
        .wrap_err("parse test SNS payment asset definition")?;
    Ok(EnsureAlias::new(
        AliasIntentV1::Domain(AliasDomainIntentV1 {
            domain: ResolvedDomainV1::new(domain.clone(), dataspace_id),
            owner: owner.clone(),
        }),
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: TEST_SNS_POLICY_VERSION,
            expected_payment_asset: payment_asset,
            max_amount: TEST_SNS_LEASE_PAYMENT.parse().expect("valid test payment"),
            valid_until_ms: u64::MAX,
        },
    ))
}
/// Build one declarative instruction that ensures a domain and its lease state.
pub fn domain_setup_instruction_in_dataspace(
    domain: &DomainId,
    dataspace_id: DataSpaceId,
    owner: &AccountId,
) -> Result<InstructionBox> {
    Ok(test_domain_setup_instruction(domain, dataspace_id, owner)?.into())
}
/// Build one declarative instruction for a deterministically mapped domain.
pub fn domain_setup_instruction(domain: &DomainId, owner: &AccountId) -> Result<InstructionBox> {
    domain_setup_instruction_in_dataspace(domain, test_domain_dataspace_id(domain)?, owner)
}
/// Build one declarative dataspace-alias setup instruction.
pub fn dataspace_setup_instruction(
    alias: &str,
    dataspace_id: DataSpaceId,
    owner: &AccountId,
) -> Result<InstructionBox> {
    let canonical_name = alias
        .parse()
        .wrap_err_with(|| format!("parse test dataspace alias `{alias}`"))?;
    let payment_asset = AssetDefinitionId::parse_address_literal(TEST_SNS_PAYMENT_ASSET_DEFINITION)
        .wrap_err("parse test SNS payment asset definition")?;
    Ok(EnsureAlias::new(
        AliasIntentV1::Dataspace(AliasDataSpaceIntentV1 {
            dataspace: ResolvedDataSpaceV1::new(canonical_name, dataspace_id),
            owner: owner.clone(),
        }),
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: TEST_SNS_POLICY_VERSION,
            expected_payment_asset: payment_asset,
            max_amount: TEST_SNS_LEASE_PAYMENT.parse().expect("valid test payment"),
            valid_until_ms: u64::MAX,
        },
    )
    .into())
}
/// Build one declarative account-alias setup instruction with an explicit dataspace mapping.
pub fn account_alias_setup_instruction_in_dataspace(
    alias_literal: &str,
    dataspace_id: DataSpaceId,
    target_account: &AccountId,
    provision: AccountProvisionV1,
    role: AccountAliasRoleV1,
) -> Result<InstructionBox> {
    let canonical_name = alias_literal
        .parse::<AccountAliasName>()
        .wrap_err_with(|| format!("parse test account alias `{alias_literal}`"))?;
    let payment_asset = AssetDefinitionId::parse_address_literal(TEST_SNS_PAYMENT_ASSET_DEFINITION)
        .wrap_err("parse test SNS payment asset definition")?;
    Ok(EnsureAlias::new(
        AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
            alias: ResolvedAccountAliasV1::new(canonical_name, dataspace_id),
            target_account: target_account.clone(),
            provision,
            role,
        }),
        AliasLeaseAcquisitionV1::new(1, None),
        AliasQuoteGuardV1 {
            expected_policy_version: TEST_SNS_POLICY_VERSION,
            expected_payment_asset: payment_asset,
            max_amount: TEST_SNS_LEASE_PAYMENT.parse().expect("valid test payment"),
            valid_until_ms: u64::MAX,
        },
    )
    .into())
}
/// Build one declarative account-alias setup instruction for a deterministically mapped alias.
pub fn account_alias_setup_instruction(
    alias_literal: &str,
    target_account: &AccountId,
    provision: AccountProvisionV1,
    role: AccountAliasRoleV1,
) -> Result<InstructionBox> {
    let parsed = alias_literal
        .parse::<AccountAliasName>()
        .wrap_err_with(|| format!("parse test account alias `{alias_literal}`"))?;
    let dataspace_id = iroha_core::sns::dataspace_id_for_sns_alias(parsed.dataspace.as_ref())
        .ok_or_else(|| eyre!("derive deterministic dataspace id for alias `{alias_literal}`"))?;
    account_alias_setup_instruction_in_dataspace(
        alias_literal,
        dataspace_id,
        target_account,
        provision,
        role,
    )
}
fn domain_alias_record_visible_to_client(client: &Client, domain: &DomainId) -> Result<bool> {
    let domain_label = domain.to_string();
    match client
        .client()
        .sns()
        .get_name(iroha::sns::SnsNamespacePath::Domain, &domain_label)
    {
        Ok(record)
            if &record.owner == client.client().account()
                && record.status == NameStatus::Active =>
        {
            Ok(true)
        }
        Ok(record) => Err(eyre!(
            "domain `{domain}` requires an active SNS lease owned by `{}`; found owner `{}` with status {:?}",
            client.client().account(),
            record.owner,
            record.status
        )),
        Err(_) => Ok(false),
    }
}
fn domain_setup_ready_to_client(client: &Client, domain: &DomainId) -> Result<bool> {
    let domain_exists = match client.client().query(FindDomains::new()).execute_all() {
        Ok(domains) => match domains.into_iter().find(|existing| existing.id() == domain) {
            Some(existing) if existing.owned_by() == client.client().account() => true,
            Some(existing) => {
                return Err(eyre!(
                    "domain `{domain}` is owned by `{}`, not setup authority `{}`",
                    existing.owned_by(),
                    client.client().account()
                ));
            }
            None => false,
        },
        Err(err) => {
            let report = Report::from(err);
            if torii_request_error_is_transient(&report) {
                debug!(
                    err = %report,
                    %domain,
                    torii_url = %client.client().endpoint(),
                    "transient domain visibility query failed while checking SNS lease readiness"
                );
                false
            } else {
                return Err(report);
            }
        }
    };
    domain_exists
        .then(|| domain_alias_record_visible_to_client(client, domain))
        .transpose()
        .map(|visible| visible.unwrap_or(false))
}
fn wait_for_domain_setup(client: &Client, domain: &DomainId) -> Result<bool> {
    let deadline = Instant::now() + TEST_SNS_LEASE_VISIBILITY_TIMEOUT;
    while Instant::now() < deadline {
        if domain_setup_ready_to_client(client, domain)? {
            return Ok(true);
        }
        std::thread::sleep(TEST_SNS_LEASE_VISIBILITY_POLL);
    }
    domain_setup_ready_to_client(client, domain)
}
/// Ensure a domain and all of its lease-derived state in one ordinary transaction.
pub fn ensure_domain_setup_in_dataspace(
    client: &Client,
    domain: &DomainId,
    dataspace_id: DataSpaceId,
) -> Result<()> {
    if domain_setup_ready_to_client(client, domain)? {
        return Ok(());
    }
    match client.submit(
        test_domain_setup_instruction(domain, dataspace_id, client.client().account())?,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    ) {
        Ok(_) => {
            if wait_for_domain_setup(client, domain)? {
                Ok(())
            } else {
                Err(eyre!(
                    "domain `{domain}` declarative setup was not visible within {:?}",
                    TEST_SNS_LEASE_VISIBILITY_TIMEOUT
                ))
            }
        }
        Err(err) => Err(err),
    }
}
/// Ensure a domain whose dataspace uses the deterministic dynamic mapping.
pub fn ensure_domain_setup(client: &Client, domain: &DomainId) -> Result<()> {
    ensure_domain_setup_in_dataspace(client, domain, test_domain_dataspace_id(domain)?)
}
/// Ensure a runtime domain registration has the SNS lease required by the executor on every peer
/// in a test network.
pub fn ensure_domain_setup_for_network(network: &Network, domain: &DomainId) -> Result<()> {
    let mut peers = network.peers().iter().collect::<Vec<_>>();
    peers.sort_by(|left, right| left.id().cmp(&right.id()));
    let clients = peers
        .into_iter()
        .map(NetworkPeer::client)
        .collect::<Vec<_>>();
    let Some((primary, replicas)) = clients.split_first() else {
        return Ok(());
    };
    ensure_domain_setup(primary, domain)?;
    for client in replicas {
        if !wait_for_domain_setup(client, domain)? {
            return Err(eyre!(
                "domain `{domain}` declarative setup was not visible to peer `{}` within {:?}",
                client.client().endpoint(),
                TEST_SNS_LEASE_VISIBILITY_TIMEOUT
            ));
        }
    }
    Ok(())
}
/// Ensure a runtime domain declaratively.
pub fn submit_ensure_domain(client: &Client, domain: NewDomain) -> Result<()> {
    if domain.logo.is_some() || !domain.metadata.is_empty() {
        return Err(eyre!(
            "declarative test domain setup requires empty immutable metadata and no logo"
        ));
    }
    ensure_domain_setup(client, &domain.id)
}
/// Ensure a runtime domain declaratively and wait for every peer to observe it.
pub fn submit_ensure_domain_for_network(
    network: &Network,
    client: &Client,
    domain: NewDomain,
) -> Result<()> {
    if client.client().account() != network.client().client().account() {
        return Err(eyre!(
            "network domain setup must be submitted by the network client authority"
        ));
    }
    if domain.logo.is_some() || !domain.metadata.is_empty() {
        return Err(eyre!(
            "declarative test domain setup requires empty immutable metadata and no logo"
        ));
    }
    ensure_domain_setup_for_network(network, &domain.id)
}
const DEFAULT_BLOCK_SYNC: Duration = Duration::from_millis(150);
// Fast signed cadence for local test networks; callers can opt into Sumeragi defaults.
const LOCALNET_BLOCK_CADENCE: Duration = Duration::from_millis(333);
// Sumeragi default, used only when the builder is explicitly told to keep it.
const DEFAULT_BLOCK_CADENCE: Duration =
    Duration::from_millis(iroha_config::parameters::defaults::sumeragi::BLOCK_CADENCE_MS);
// Allow generous shutdowns in multi-peer tests; peers may need to flush logs and close streams.
const PEER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
const STORAGE_LISTING_LIMIT: usize = 8;
const SNAPSHOT_MESSAGE_SNIPPET_MAX_CHARS: usize = 512;
const PEER_STARTUP_TIMEOUT_PER_PEER_SECS: u64 = 60;
const NON_OPTIMIZED_IVM_FUEL: NonZero<u64> = nonzero!(1_000_000_000u64);
/// Minimum signed block cadence accepted by `with_block_cadence` (milliseconds).
const MIN_BLOCK_CADENCE_MS: u64 = 1;
/// Interval at which we emit watchdog logs while waiting for block 1.
const GENESIS_BLOCK_LOG_INTERVAL: Duration = Duration::from_secs(10);
const POST_GENESIS_LIVENESS_WINDOW: Duration = Duration::from_secs(5);
const DEFAULT_NETWORK_PEERS: usize = 4;
const SERIALIZE_NETWORKS_ENV: &str = "IROHA_TEST_SERIALIZE_NETWORKS";
const NETWORK_PARALLELISM_ENV: &str = "IROHA_TEST_NETWORK_PARALLELISM";
const NETWORK_PERMIT_DIR_ENV: &str = "IROHA_TEST_NETWORK_PERMIT_DIR";
const NETWORK_PERMIT_WAIT_TIMEOUT_ENV: &str = "IROHA_TEST_NETWORK_PERMIT_WAIT_TIMEOUT";
const NETWORK_PERMIT_WAIT_TIMEOUT_DEFAULT: Duration = Duration::from_secs(5 * 60);
const BUILD_COMMAND_TIMEOUT_ENV: &str = "IROHA_TEST_BUILD_TIMEOUT_MS";
const BUILD_COMMAND_TIMEOUT_DEFAULT: Duration = Duration::from_secs(20 * 60);
const NETWORK_PERMIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const NETWORK_PERMIT_LOG_INTERVAL: Duration = Duration::from_secs(60);
const NETWORK_PERMIT_STALE_TTL: Duration = Duration::from_secs(60 * 60 * 12);
// Keep test-network parallelism conservative; DA-heavy suites are resource intensive.
const DEFAULT_NETWORK_PARALLELISM_PEERS: usize = 64;
const DEFAULT_NETWORK_PARALLELISM_LIMIT: usize = 1;
const TEST_CONCURRENCY_OVERSUBSCRIPTION: usize = 2;
const TEST_CONCURRENCY_MIN_THREADS: usize = 4;
const PERMISSIONED_BLS_DOMAIN: &str = "bls-iroha3:permissioned-sumeragi:v1";
const NPOS_BLS_DOMAIN: &str = "bls-iroha3:npos-sumeragi:v1";
#[cfg(test)]
const PIPELINE_SIDECARS_DATA_FILE: &str = "sidecars.norito";
#[cfg(test)]
const PIPELINE_SIDECARS_INDEX_FILE: &str = "sidecars.index";
#[cfg(test)]
const PIPELINE_INDEX_ENTRY_SIZE: usize = core::mem::size_of::<u64>() * 2;
#[cfg(test)]
const PIPELINE_INDEX_ENTRY_SIZE_U64: u64 = PIPELINE_INDEX_ENTRY_SIZE as u64;
/// Grace period before we start emitting warning-level status poll failures during startup.
/// This keeps integration test output quieter while peers are still binding sockets.
const STARTUP_STATUS_WARN_GRACE: Duration = Duration::from_secs(5);
/// Minimum spacing between repeated warning logs for startup status failures after the grace.
const STARTUP_STATUS_WARN_INTERVAL: Duration = Duration::from_secs(5);
/// Low-priority `/status` fallback cadence after startup has already been observed.
const STATUS_FALLBACK_INTERVAL: Duration = Duration::from_secs(2);
type GenesisBuilderFn = Arc<
    dyn Fn(
            UniqueVec<PeerId>,
            Vec<GenesisTopologyEntry>,
            Vec<PeerId>,
            Vec<GenesisTopologyEntry>,
            Vec<PeerId>,
            Vec<GenesisTopologyEntry>,
        ) -> GenesisBlock
        + Send
        + Sync
        + 'static,
>;
fn revision4_committee_at_least(min_peers: usize) -> Option<usize> {
    (MIN_VALIDATORS_PER_HEIGHT..=MAX_VALIDATORS_PER_HEIGHT)
        .step_by(3)
        .find(|peers| *peers >= min_peers)
}
fn assert_genesis_voting_roster_matches_network(genesis: &GenesisBlock, expected_peers: &[PeerId]) {
    let actual = genesis_committee_peers(&genesis.0)
        .unwrap_or_else(|error| {
            panic!("test-network genesis has an invalid voting roster: {error}")
        })
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected = expected_peers.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "signed test-network genesis voting roster must exactly match the guarded validator topology"
    );
}
fn read_env_duration(var: &str, default: Duration) -> Duration {
    if let Ok(val) = std::env::var(var) {
        // Accept seconds or ms suffix (e.g., "45" or "4500ms")
        let trimmed = val.trim();
        if let Some(ms) = trimmed.strip_suffix("ms")
            && let Ok(n) = ms.parse::<u64>()
        {
            return Duration::from_millis(n);
        }
        if let Ok(n) = trimmed.parse::<u64>() {
            return Duration::from_secs(n);
        }
    }
    default
}
fn build_command_timeout_env() -> Duration {
    read_env_duration(BUILD_COMMAND_TIMEOUT_ENV, BUILD_COMMAND_TIMEOUT_DEFAULT)
}
fn command_output_with_timeout(
    command: &mut std::process::Command,
    timeout: Duration,
) -> std::io::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let command_debug = format!("{command:?}");
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().map(read_pipe);
    let stderr = child.stderr.take().map(read_pipe);
    let Some(status) = wait_for_child_exit(&mut child, timeout)? else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = join_pipe(stdout);
        let _ = join_pipe(stderr);
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("command {command_debug} timed out after {timeout:?}"),
        ));
    };
    Ok(Output {
        status,
        stdout: join_pipe(stdout),
        stderr: join_pipe(stderr),
    })
}
fn read_pipe<R>(mut pipe: R) -> thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        bytes
    })
}
fn join_pipe(handle: Option<thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
}
fn wait_for_child_exit(
    child: &mut std::process::Child,
    timeout: Duration,
) -> std::io::Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(None);
        }
        thread::sleep(NETWORK_PERMIT_POLL_INTERVAL.min(timeout.saturating_sub(elapsed)));
    }
}
fn unix_timestamp_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}
/// Tracks whether startup warning messages should be emitted or downgraded.
#[derive(Clone)]
struct StartupWarnGate {
    started_at: Instant,
    grace: Duration,
    interval: Duration,
    last_warn: Arc<StdMutex<Option<Instant>>>,
}
impl StartupWarnGate {
    fn new(grace: Duration) -> Self {
        Self::with_interval(grace, STARTUP_STATUS_WARN_INTERVAL)
    }
    fn with_interval(grace: Duration, interval: Duration) -> Self {
        Self {
            started_at: Instant::now(),
            grace,
            interval,
            last_warn: Arc::new(StdMutex::new(None)),
        }
    }
    fn should_warn(&self) -> bool {
        if self.started_at.elapsed() < self.grace {
            return false;
        }
        let now = Instant::now();
        let mut last_warn = self
            .last_warn
            .lock()
            .expect("warn gate should not be poisoned");
        if let Some(last) = *last_warn
            && now.duration_since(last) < self.interval
        {
            return false;
        }
        *last_warn = Some(now);
        true
    }
}
fn log_status_warning(gate: &StartupWarnGate, warn_log: impl FnOnce(), debug_log: impl FnOnce()) {
    if gate.should_warn() {
        warn_log();
    } else {
        debug_log();
    }
}
fn status_error_is_connection_refused(err: &Report) -> bool {
    err.chain().any(|cause| {
        if let Some(iroha::Error::Transport { kind, .. }) = cause.downcast_ref::<iroha::Error>()
            && matches!(
                kind,
                iroha::TransportErrorKind::Io(ErrorKind::ConnectionRefused)
            )
        {
            return true;
        }
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == ErrorKind::ConnectionRefused)
    })
}
fn status_error_is_torii_query_backpressure(err: &Report) -> bool {
    err.chain().any(|cause| {
        if let Some(iroha::Error::Http { status, body, .. }) = cause.downcast_ref::<iroha::Error>()
        {
            return *status == 429
                && std::str::from_utf8(body)
                    .is_ok_and(|text| text.contains("Reached the limit of parallel queries"));
        }
        let message = cause.to_string();
        message.contains("429 Too Many Requests")
            && message.contains("Reached the limit of parallel queries")
    })
}
fn torii_request_error_is_transient(err: &Report) -> bool {
    if status_error_is_connection_refused(err) || status_error_is_torii_query_backpressure(err) {
        return true;
    }
    let mut saw_http_transport = false;
    let mut saw_transient_transport = false;
    for cause in err.chain() {
        if matches!(
            cause.downcast_ref::<iroha::Error>(),
            Some(
                iroha::Error::Timeout { .. }
                    | iroha::Error::Transport {
                        kind: iroha::TransportErrorKind::Io(
                            ErrorKind::ConnectionReset
                                | ErrorKind::ConnectionAborted
                                | ErrorKind::BrokenPipe
                                | ErrorKind::UnexpectedEof
                                | ErrorKind::TimedOut
                        ),
                        ..
                    }
            )
        ) {
            return true;
        }
        let message = cause.to_string();
        saw_http_transport |= message.contains("Failed to send http")
            || message.contains("error sending request for url")
            || message.contains("client error (Connect)")
            || message.contains("tcp connect error");
        saw_transient_transport |= message.contains("operation timed out")
            || message.contains("request timed out")
            || message.contains("Connection refused")
            || message.contains("connection refused")
            || message.contains("connection reset")
            || message.contains("connection closed");
    }
    saw_http_transport && saw_transient_transport
}
/// Try binding to all provided addresses to detect missing socket permissions early.
fn preflight_bind_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> std::io::Result<()> {
    for addr in addresses {
        let listener = TcpListener::bind(addr)?;
        drop(listener);
    }
    Ok(())
}
fn should_run_bind_preflight_for_runs_started(runs_started: usize) -> bool {
    // Only probe sockets before the first start attempt. Restarting a peer or a full
    // network after a partial bootstrap can briefly leave API/P2P ports in a kernel
    // cleanup state, and the actual `irohad`/Tokio listeners are a better source of truth
    // than this best-effort preflight probe on those retries.
    runs_started == 0
}
fn sync_timeout_env() -> Duration {
    // Default 60s; override with IROHA_TEST_SYNC_TIMEOUT_SECS or *_MS
    let secs = read_env_duration("IROHA_TEST_SYNC_TIMEOUT_SECS", Duration::from_secs(0));
    if secs != Duration::from_secs(0) {
        return secs;
    }
    // Keep override available for slower hosts; default to 180s to tolerate heavier fixtures.
    read_env_duration("IROHA_TEST_SYNC_TIMEOUT_MS", Duration::from_secs(180))
}
fn peer_start_timeout_env() -> Duration {
    // Default to the sync timeout; override with IROHA_TEST_PEER_START_TIMEOUT_SECS or *_MS.
    let secs = read_env_duration("IROHA_TEST_PEER_START_TIMEOUT_SECS", Duration::from_secs(0));
    if secs != Duration::from_secs(0) {
        return secs;
    }
    // Keep generous but finite default to tolerate heavier genesis without hanging forever.
    read_env_duration("IROHA_TEST_PEER_START_TIMEOUT_MS", sync_timeout_env())
}
const CLIENT_STATUS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(600);
const CLIENT_TTL_DEFAULT: Duration = Duration::from_secs(1200);
const CLIENT_TTL_MIN_SLACK: Duration = Duration::from_secs(120);
fn client_status_timeout_env() -> Duration {
    // Default 600s; override with IROHA_TEST_CLIENT_STATUS_TIMEOUT_SECS or *_MS
    let secs = read_env_duration(
        "IROHA_TEST_CLIENT_STATUS_TIMEOUT_SECS",
        Duration::from_secs(0),
    );
    if secs != Duration::from_secs(0) {
        return secs;
    }
    // Keep bounded to avoid long hangs when Torii is unreachable.
    read_env_duration(
        "IROHA_TEST_CLIENT_STATUS_TIMEOUT_MS",
        CLIENT_STATUS_TIMEOUT_DEFAULT,
    )
}
fn client_request_timeout_env() -> Duration {
    // Keep the integration-client default aligned with the client library's
    // routed Torii budget; override with IROHA_TEST_CLIENT_REQUEST_TIMEOUT_SECS or *_MS.
    let secs = read_env_duration(
        "IROHA_TEST_CLIENT_REQUEST_TIMEOUT_SECS",
        Duration::from_secs(0),
    );
    if secs != Duration::from_secs(0) {
        return secs;
    }
    read_env_duration(
        "IROHA_TEST_CLIENT_REQUEST_TIMEOUT_MS",
        iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
    )
}
fn client_ttl_env(status_timeout: Duration) -> Duration {
    let secs = read_env_duration("IROHA_TEST_CLIENT_TTL_SECS", Duration::ZERO);
    let ttl = if secs != Duration::ZERO {
        secs
    } else {
        read_env_duration("IROHA_TEST_CLIENT_TTL_MS", CLIENT_TTL_DEFAULT)
    };
    let min_ttl = status_timeout + CLIENT_TTL_MIN_SLACK;
    if ttl <= min_ttl {
        // Ensure TTL meaningfully exceeds the status timeout so slow consensus does not expire txs.
        min_ttl
    } else {
        ttl
    }
}
fn post_genesis_liveness_window_env() -> Duration {
    read_env_duration(
        "IROHA_TEST_POST_GENESIS_LIVENESS_MS",
        POST_GENESIS_LIVENESS_WINDOW,
    )
}
fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}
const TEMPDIR_PREFIX: &str = "irohad_test_network_";
const TEMPDIR_IN_ENV: &str = "TEST_NETWORK_TMP_DIR";
const TEMPDIR_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const TEMPDIR_MAX_KEEP: usize = 256;
const KEEP_TEMPDIR_ENV: &str = "IROHA_TEST_NETWORK_KEEP_DIRS";
const PROGRAM_IROHAD_TAIRA_ENV: &str = "TEST_NETWORK_BIN_IROHAD_TAIRA";
const PROGRAM_IROHAD_ENV: &str = "TEST_NETWORK_BIN_IROHAD";
const PROGRAM_IROHAD_PRIVATE_SETTLEMENT_ROUTES_ENV: &str =
    "TEST_NETWORK_BIN_IROHAD_PRIVATE_SETTLEMENT_ROUTES";
const PROGRAM_IROHAD_PARLIAMENT_SIGNERS_ENV: &str = "TEST_NETWORK_BIN_IROHAD_PARLIAMENT_SIGNERS";
const PROGRAM_IROHAD_FEATURES_ENV: &str = "TEST_NETWORK_IROHAD_FEATURES";
const PROGRAM_IROHA_ENV: &str = "TEST_NETWORK_BIN_IROHA";
/// Locate the build checkout without requiring it to exist on this host.
fn compiled_repo_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("test network crate must be under the workspace crates directory")
        .to_path_buf()
}
/// Utility to get the root of the repository
pub fn repo_root() -> PathBuf {
    compiled_repo_path().canonicalize().unwrap()
}
const DEFAULT_RANS_TABLES: &[u8] = include_bytes!("../../../codec/rans/tables/rans_seed0.toml");
fn tempdir_in() -> Option<impl AsRef<Path>> {
    static ENV: OnceLock<Option<PathBuf>> = OnceLock::new();
    ENV.get_or_init(|| std::env::var(TEMPDIR_IN_ENV).map(PathBuf::from).ok())
        .as_ref()
}
fn prune_stale_tempdirs() {
    let base = tempdir_in()
        .map(|p| p.as_ref().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let Ok(read) = fs::read_dir(&base) else {
        return;
    };
    let mut entries: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if !name.starts_with(TEMPDIR_PREFIX) {
                continue;
            }
        } else {
            continue;
        }
        if let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
        {
            entries.push((path, modified));
        }
    }
    // Newest first
    entries.sort_by_key(|(_, m)| std::cmp::Reverse(*m));
    let now = std::time::SystemTime::now();
    let mut kept = 0;
    for (path, modified) in entries {
        if kept >= TEMPDIR_MAX_KEEP {
            let _ = fs::remove_dir_all(&path);
            continue;
        }
        if let Ok(age) = now.duration_since(modified)
            && age > TEMPDIR_MAX_AGE
        {
            let _ = fs::remove_dir_all(&path);
            continue;
        }
        kept += 1;
    }
}
fn init_logger_once() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = tracing_subscriber::registry()
            .with(env_filter_from_env_or_default())
            .with(
                tracing_subscriber::fmt::layer().with_timer(tracing_subscriber::fmt::time::time()),
            )
            .try_init();
    });
}
/// Build the `EnvFilter` used for test network logs.
///
/// Honors `RUST_LOG` if it is set; otherwise falls back to a calmer `warn` level
/// so that integration tests do not overwhelm the output buffer with informational
/// or debug messages unless explicitly requested by the developer.
fn env_filter_from_env_or_default() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
}
trait CommandEnv {
    fn env_remove(&mut self, key: &str);
}
impl CommandEnv for tokio::process::Command {
    fn env_remove(&mut self, key: &str) {
        tokio::process::Command::env_remove(self, key);
    }
}
fn config_env_override_keys() -> &'static [&'static str] {
    static KEYS: OnceLock<Vec<&'static str>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let source = include_str!("../../iroha_config/src/parameters/user.rs");
        let mut keys = Vec::new();
        let mut offset = 0;
        const MARKER: &str = "env = \"";
        while let Some(pos) = source[offset..].find(MARKER) {
            let start = offset + pos + MARKER.len();
            let Some(end_rel) = source[start..].find('"') else {
                break;
            };
            let end = start + end_rel;
            let key = &source[start..end];
            if !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                keys.push(key);
            }
            offset = end + 1;
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    })
}
fn strip_config_env_overrides(cmd: &mut impl CommandEnv) {
    // Prevent developer env overrides from shadowing test network configs.
    for key in config_env_override_keys() {
        cmd.env_remove(key);
    }
}
fn generate_and_keep_temp_dir() -> PathBuf {
    prune_stale_tempdirs();
    let mut builder = tempfile::Builder::new();
    builder.prefix(TEMPDIR_PREFIX).disable_cleanup(true);
    match tempdir_in() {
        Some(create_within) => builder.tempdir_in(create_within),
        None => builder.tempdir(),
    }
    .expect("tempdir creation should work")
    .path()
    .to_path_buf()
}
/// Environment of a specific test network.
///
/// Configures things such as the temporary directory with all artifacts or the binaries to use.
///
/// Shared across [`Network`] and [`NetworkPeer`].
#[derive(Debug)]
pub struct Environment {
    /// Working directory
    dir: PathBuf,
}
// tests module lives at the end of file
/// Programs to work with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Program {
    /// Iroha Daemon CLI
    Irohad,
    /// Feature-isolated daemon used only by explicit consensus fault-injection tests.
    #[doc(hidden)]
    IrohadPrivateSettlementRoutes,
    /// Feature-isolated daemon with exact-seat Parliament beacon and TLE share providers.
    #[doc(hidden)]
    IrohadParliamentSigners,
    /// Feature-isolated stock-custody broker for disposable peer networks.
    #[doc(hidden)]
    IrohadDisposableBroker,
    /// Shipping Taira launcher, including its offline production beacon bootstrap.
    IrohadTaira,
    /// Iroha Client CLI
    Iroha,
}

/// Feature-isolated global-beacon signer behavior for one validator child.
///
/// The mode changes only the test daemon's runtime beacon-share provider. The
/// validator remains online, retains its full consensus vote, and always keeps
/// the proof-valid Parliament TLE signer installed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ParliamentBeaconSignerMode {
    /// Produce and broadcast the proof-valid share for the exact local seat.
    #[default]
    Valid,
    /// Do not install a global-beacon partial signer for this validator.
    Absent,
    /// Broadcast a deliberately proof-invalid share without admitting it locally.
    Invalid,
}

const PARLIAMENT_BEACON_SIGNER_MODE_ARG: &str = "--test-network-parliament-beacon-signer-mode";
const PARLIAMENT_TEST_SIGNER_VALIDATOR_COUNT: usize = 4;

impl ParliamentBeaconSignerMode {
    const fn child_arg(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Absent => "absent",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug)]
struct ProgramSpec {
    name: &'static str,
    env: &'static str,
    pkg: &'static str,
    build_args: Vec<OsString>,
    isolated_target_subdir: Option<&'static str>,
}
impl Program {
    const fn release_prebuilt_binary(self) -> ReleasePrebuiltBinary {
        match self {
            Self::Irohad => ReleasePrebuiltBinary::Irohad,
            Self::IrohadTaira => ReleasePrebuiltBinary::IrohadTaira,
            Self::IrohadPrivateSettlementRoutes => ReleasePrebuiltBinary::Irohad,
            // The test signer is explicitly rejected whenever a release-prebuilt
            // contract is active. This value is therefore an unreachable sentinel.
            Self::IrohadParliamentSigners => ReleasePrebuiltBinary::Irohad,
            Self::IrohadDisposableBroker => ReleasePrebuiltBinary::Irohad,
            Self::Iroha => ReleasePrebuiltBinary::Iroha,
        }
    }
    const fn release_prebuilt_allowed(self) -> bool {
        !matches!(
            self,
            Self::IrohadParliamentSigners
                | Self::IrohadDisposableBroker
                | Self::IrohadPrivateSettlementRoutes
        )
    }
    fn spec(&self) -> ProgramSpec {
        match self {
            Self::Irohad => ProgramSpec {
                name: "iroha3d",
                env: PROGRAM_IROHAD_ENV,
                pkg: "irohad",
                build_args: {
                    let mut args: Vec<OsString> = ["--bin", "iroha3d"]
                        .into_iter()
                        .map(OsString::from)
                        .collect();
                    if let Ok(features) = std::env::var(PROGRAM_IROHAD_FEATURES_ENV) {
                        let trimmed = features.trim();
                        if !trimmed.is_empty() {
                            args.push(OsString::from("--features"));
                            args.push(OsString::from(trimmed));
                        }
                    }
                    args
                },
                isolated_target_subdir: None,
            },
            Self::IrohadPrivateSettlementRoutes => ProgramSpec {
                name: "iroha3d",
                env: PROGRAM_IROHAD_PRIVATE_SETTLEMENT_ROUTES_ENV,
                pkg: "irohad",
                build_args: [
                    "--bin",
                    "iroha3d",
                    "--features",
                    "test-network-private-settlement-route-control",
                ]
                .into_iter()
                .map(OsString::from)
                .collect(),
                isolated_target_subdir: Some("private-settlement-route-control"),
            },
            Self::IrohadParliamentSigners => ProgramSpec {
                name: "iroha3d",
                env: PROGRAM_IROHAD_PARLIAMENT_SIGNERS_ENV,
                pkg: "irohad",
                build_args: [
                    "--bin",
                    "iroha3d",
                    "--features",
                    "test-network-parliament-signers",
                ]
                .into_iter()
                .map(OsString::from)
                .collect(),
                isolated_target_subdir: Some("parliament-signers"),
            },
            Self::IrohadDisposableBroker => ProgramSpec {
                name: "iroha_test_runtime_provider_broker",
                env: "TEST_NETWORK_BIN_IROHAD_DISPOSABLE_BROKER",
                pkg: "irohad",
                build_args: [
                    "--bin",
                    "iroha_test_runtime_provider_broker",
                    "--features",
                    "test-network-disposable-broker",
                ]
                .into_iter()
                .map(OsString::from)
                .collect(),
                isolated_target_subdir: Some("disposable-broker"),
            },
            Self::IrohadTaira => ProgramSpec {
                name: "iroha3d_taira",
                env: PROGRAM_IROHAD_TAIRA_ENV,
                pkg: "irohad",
                build_args: ["--bin", "iroha3d_taira"]
                    .into_iter()
                    .map(OsString::from)
                    .collect(),
                isolated_target_subdir: None,
            },
            Self::Iroha => ProgramSpec {
                name: "iroha",
                env: PROGRAM_IROHA_ENV,
                pkg: "iroha_cli",
                build_args: Vec::new(),
                isolated_target_subdir: None,
            },
        }
    }
}
// Cache resolved binary paths to avoid redundant rebuilds/resolution per peer
static IROHAD_TAIRA_BIN: OnceLock<PathBuf> = OnceLock::new();
static IROHAD_BIN: OnceLock<PathBuf> = OnceLock::new();
static IROHAD_PRIVATE_SETTLEMENT_ROUTES_BIN: OnceLock<PathBuf> = OnceLock::new();
static IROHAD_PARLIAMENT_SIGNERS_BIN: OnceLock<PathBuf> = OnceLock::new();
static IROHAD_DISPOSABLE_BROKER_BIN: OnceLock<PathBuf> = OnceLock::new();
static IROHA_BIN: OnceLock<PathBuf> = OnceLock::new();
const BUILD_CACHE_DIR: &str = ".iroha_test_network";
const BUILD_STAMP_VERSION: u32 = 3;
const IROHA_TEST_TARGET_DIR_ENV: &str = "IROHA_TEST_TARGET_DIR";
const IROHA_TEST_BUILD_PROFILE_ENV: &str = "IROHA_TEST_BUILD_PROFILE";
const IROHA_TEST_SKIP_BUILD_ENV: &str = "IROHA_TEST_SKIP_BUILD";
const IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV: &str = "IROHA_RELEASE_SOURCE_MANIFEST_SHA256";
const IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV: &str = "IROHA_RELEASE_PREBUILT_MANIFEST_SHA256";
const IROHA_RELEASE_CARGO_LOCK_SHA256_ENV: &str = "IROHA_RELEASE_CARGO_LOCK_SHA256";
const IROHA_RELEASE_ARTIFACT_ROOT_ENV: &str = "IROHA_RELEASE_ARTIFACT_ROOT";
const IROHA_TEST_TARGET_SUBDIR: &str = "iroha-test-network";
const SUMERAGI_RELEASE_TARGET_SUBDIR: &str = "sumeragi-release";
const SUMERAGI_RELEASE_PROGRAMS_SUBDIR: &str = "programs";
const SUMERAGI_RELEASE_INVOCATION_PREFIX: &str = "invocation.";
const SUMERAGI_PREBUILT_MANIFEST: &str = ".sumeragi-prebuilt-binaries.tsv";
const SUMERAGI_PREBUILT_MANIFEST_SCHEMA_VERSION: &str = "2";
const MAX_SUMERAGI_PREBUILT_MANIFEST_BYTES: u64 = 32 * 1024;
const MAX_SUMERAGI_PREBUILT_BINARY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_WORKSPACE_CARGO_LOCK_BYTES: u64 = 16 * 1024 * 1024;
const RELEASE_BINARY_MODE_OCTAL: &str = "0500";
const RELEASE_BINARY_MODE: u32 = 0o500;
const RELEASE_MANIFEST_MODE: u32 = 0o400;
#[derive(Debug, Clone)]
struct BuildStamp {
    fingerprint: u64,
    profile: String,
    binary: PathBuf,
}
/// One executable covered by the source-bound release prebuild manifest.
#[doc(hidden)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReleasePrebuiltBinary {
    Irohad,
    Iroha,
    Kagami,
    IrohadTaira,
}
impl ReleasePrebuiltBinary {
    const ALL: [Self; 4] = [Self::Irohad, Self::Iroha, Self::Kagami, Self::IrohadTaira];
    const fn manifest_prefix(self) -> &'static str {
        match self {
            Self::Irohad => "irohad",
            Self::Iroha => "iroha",
            Self::Kagami => "kagami",
            Self::IrohadTaira => "irohad_taira",
        }
    }
    const fn relative_path(self) -> &'static str {
        match self {
            Self::Irohad => "release/iroha3d",
            Self::Iroha => "release/iroha",
            Self::Kagami => "release/kagami",
            Self::IrohadTaira => "release/iroha3d_taira",
        }
    }
}
#[derive(Debug, Clone)]
struct ReleaseBinaryAttestation {
    kind: ReleasePrebuiltBinary,
    sha256: String,
    size_bytes: u64,
}
#[derive(Debug, Clone)]
struct ReleaseProgramContract {
    configured_target_dir: PathBuf,
    canonical_target_dir: PathBuf,
    binaries: [ReleaseBinaryAttestation; 4],
}
impl ReleaseProgramContract {
    fn binary(&self, kind: ReleasePrebuiltBinary) -> &ReleaseBinaryAttestation {
        self.binaries
            .iter()
            .find(|entry| entry.kind == kind)
            .expect("release manifest contains every fixed binary kind")
    }
}
fn resolve_target_dir_path(repo: &Path, raw: &str) -> PathBuf {
    let candidate = PathBuf::from(raw);
    if candidate.is_absolute() {
        candidate
    } else {
        repo.join(candidate)
    }
}
/// Resolve the target directory for test-network builds and artifact lookup.
fn resolve_target_dir(repo: &Path) -> PathBuf {
    if let Ok(path) = std::env::var(IROHA_TEST_TARGET_DIR_ENV) {
        return resolve_target_dir_path(repo, &path);
    }
    if let Ok(path) = std::env::var("CARGO_TARGET_DIR") {
        return resolve_target_dir_path(repo, &path).join(IROHA_TEST_TARGET_SUBDIR);
    }
    repo.join("target").join(IROHA_TEST_TARGET_SUBDIR)
}
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
fn exact_env_value(key: &str) -> color_eyre::Result<Option<String>> {
    match std::env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(eyre!("{key} must contain valid Unicode")),
    }
}
#[cfg(unix)]
fn authenticate_release_artifact_root(repo: &Path, raw: &str) -> color_eyre::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;

    let configured = PathBuf::from(raw);
    if !configured.is_absolute() {
        return Err(eyre!(
            "release binary resolution requires an absolute {IROHA_RELEASE_ARTIFACT_ROOT_ENV}"
        ));
    }
    let metadata = fs::symlink_metadata(&configured).wrap_err_with(|| {
        eyre!(
            "failed to inspect release artifact root {}",
            configured.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(eyre!(
            "{IROHA_RELEASE_ARTIFACT_ROOT_ENV} must name a real directory, not a symlink"
        ));
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err(eyre!(
            "{IROHA_RELEASE_ARTIFACT_ROOT_ENV} must be an effective-user-owned private directory with exact mode 0700"
        ));
    }
    let canonical = configured.canonicalize().wrap_err_with(|| {
        eyre!(
            "failed to canonicalize release artifact root {}",
            configured.display()
        )
    })?;
    if canonical != configured {
        return Err(eyre!(
            "{IROHA_RELEASE_ARTIFACT_ROOT_ENV} must be absolute, normalized, and contain no symlinked components"
        ));
    }
    let canonical_repo = repo
        .canonicalize()
        .wrap_err("failed to canonicalize repository root for release artifact isolation")?;
    if canonical.starts_with(&canonical_repo) || canonical_repo.starts_with(&canonical) {
        return Err(eyre!(
            "{IROHA_RELEASE_ARTIFACT_ROOT_ENV} must not overlap repository source"
        ));
    }
    Ok(canonical)
}
#[cfg(not(unix))]
fn authenticate_release_artifact_root(_repo: &Path, _raw: &str) -> color_eyre::Result<PathBuf> {
    Err(eyre!(
        "release artifact root authentication requires Unix ownership and mode semantics"
    ))
}
#[cfg(unix)]
fn validate_published_mode_and_links(
    metadata: &fs::Metadata,
    expected_mode: u32,
    label: &str,
) -> color_eyre::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o7777 != expected_mode {
        return Err(eyre!(
            "{label} must have exact mode {expected_mode:04o}; got {:04o}",
            metadata.mode() & 0o7777
        ));
    }
    if metadata.nlink() != 1 {
        return Err(eyre!(
            "{label} must have exactly one hard link; got {}",
            metadata.nlink()
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_published_mode_and_links(
    _metadata: &fs::Metadata,
    _expected_mode: u32,
    _label: &str,
) -> color_eyre::Result<()> {
    Ok(())
}
#[cfg(unix)]
fn validate_published_directory_mode(
    metadata: &fs::Metadata,
    expected_mode: u32,
    label: &str,
) -> color_eyre::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o7777 != expected_mode {
        return Err(eyre!(
            "{label} must have exact mode {expected_mode:04o}; got {:04o}",
            metadata.mode() & 0o7777
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn validate_published_directory_mode(
    _metadata: &fs::Metadata,
    _expected_mode: u32,
    _label: &str,
) -> color_eyre::Result<()> {
    Ok(())
}
fn published_regular_file_metadata(
    path: &Path,
    expected_mode: u32,
    label: &str,
) -> color_eyre::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| eyre!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(eyre!(
            "{label} {} must be a regular, non-symlink file",
            path.display()
        ));
    }
    validate_published_mode_and_links(&metadata, expected_mode, label)?;
    Ok(metadata)
}
fn published_directory_metadata(
    path: &Path,
    expected_mode: u32,
    label: &str,
) -> color_eyre::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| eyre!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(eyre!(
            "{label} {} must be a directory, not a symlink",
            path.display()
        ));
    }
    validate_published_directory_mode(&metadata, expected_mode, label)?;
    Ok(metadata)
}
#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}
#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}
fn read_release_manifest(path: &Path) -> color_eyre::Result<Vec<u8>> {
    let before =
        published_regular_file_metadata(path, RELEASE_MANIFEST_MODE, "release prebuilt manifest")?;
    if before.len() > MAX_SUMERAGI_PREBUILT_MANIFEST_BYTES {
        return Err(eyre!(
            "release prebuilt manifest exceeds {} byte limit",
            MAX_SUMERAGI_PREBUILT_MANIFEST_BYTES
        ));
    }
    let mut file = fs::File::open(path).wrap_err_with(|| {
        eyre!(
            "failed to open release prebuilt manifest {}",
            path.display()
        )
    })?;
    let opened = file
        .metadata()
        .wrap_err("failed to inspect opened release prebuilt manifest")?;
    if !same_file_identity(&before, &opened) {
        return Err(eyre!(
            "release prebuilt manifest changed while it was being opened"
        ));
    }
    let capacity = usize::try_from(before.len())
        .unwrap_or(usize::MAX)
        .min(MAX_SUMERAGI_PREBUILT_MANIFEST_BYTES as usize);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(MAX_SUMERAGI_PREBUILT_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .wrap_err("failed to read release prebuilt manifest")?;
    if bytes.len() as u64 > MAX_SUMERAGI_PREBUILT_MANIFEST_BYTES {
        return Err(eyre!(
            "release prebuilt manifest exceeds {} byte limit",
            MAX_SUMERAGI_PREBUILT_MANIFEST_BYTES
        ));
    }
    let after =
        published_regular_file_metadata(path, RELEASE_MANIFEST_MODE, "release prebuilt manifest")?;
    if !same_file_identity(&opened, &after) {
        return Err(eyre!(
            "release prebuilt manifest changed while it was being read"
        ));
    }
    Ok(bytes)
}
fn hash_workspace_cargo_lock(repo: &Path) -> color_eyre::Result<String> {
    let path = repo.join("Cargo.lock");
    let metadata = fs::symlink_metadata(&path)
        .wrap_err_with(|| eyre!("failed to inspect workspace Cargo.lock {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(eyre!(
            "workspace Cargo.lock {} must be a regular, non-symlink file",
            path.display()
        ));
    }
    let file = fs::File::open(&path)
        .wrap_err_with(|| eyre!("failed to open workspace Cargo.lock {}", path.display()))?;
    let (digest, size) = sha256_reader_bounded(file, MAX_WORKSPACE_CARGO_LOCK_BYTES)
        .wrap_err("failed to hash bounded workspace Cargo.lock")?;
    if size != metadata.len() {
        return Err(eyre!("workspace Cargo.lock changed while it was hashed"));
    }
    Ok(lowercase_hex(&digest))
}
fn parse_canonical_size(value: &str, label: &str) -> color_eyre::Result<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(eyre!(
            "{label} must be a canonical unsigned decimal integer"
        ));
    }
    value
        .parse::<u64>()
        .wrap_err_with(|| eyre!("{label} does not fit u64"))
}
fn validate_target_triple(value: &str, label: &str) -> color_eyre::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(eyre!("{label} is not a bounded canonical target triple"));
    }
    Ok(())
}
fn parse_release_prebuilt_manifest(
    bytes: &[u8],
    source_manifest_sha256: &str,
    configured_target: &Path,
    repo: &Path,
) -> color_eyre::Result<[ReleaseBinaryAttestation; 4]> {
    const KEYS: [&str; 25] = [
        "schema_version",
        "source_manifest_sha256",
        "cargo_lock_sha256",
        "cargo_version_sha256",
        "rustc_version_sha256",
        "host_triple",
        "target_triple",
        "profile",
        "bundle_dir",
        "irohad_relative_path",
        "irohad_sha256",
        "irohad_size_bytes",
        "irohad_mode_octal",
        "iroha_relative_path",
        "iroha_sha256",
        "iroha_size_bytes",
        "iroha_mode_octal",
        "kagami_relative_path",
        "kagami_sha256",
        "kagami_size_bytes",
        "kagami_mode_octal",
        "irohad_taira_relative_path",
        "irohad_taira_sha256",
        "irohad_taira_size_bytes",
        "irohad_taira_mode_octal",
    ];
    const FIELD_COUNT: usize = 25;
    const BASE_FIELD_COUNT: usize = 9;
    let text = std::str::from_utf8(bytes)
        .wrap_err("release prebuilt manifest must contain valid UTF-8")?;
    if !text.ends_with('\n') || text.contains('\r') || text.contains('\0') {
        return Err(eyre!(
            "release prebuilt manifest must use canonical LF-terminated TSV"
        ));
    }
    let lines = text.strip_suffix('\n').expect("checked suffix");
    let rows = lines.split('\n').collect::<Vec<_>>();
    if rows.len() != FIELD_COUNT {
        return Err(eyre!(
            "release prebuilt manifest must contain exactly {FIELD_COUNT} fields; got {}",
            rows.len()
        ));
    }
    let mut values = Vec::with_capacity(FIELD_COUNT);
    for (index, (row, expected_key)) in rows.iter().zip(KEYS).enumerate() {
        let mut fields = row.split('\t');
        let key = fields.next().expect("split always yields key");
        let value = fields
            .next()
            .ok_or_else(|| eyre!("release prebuilt manifest row {} is not TSV", index + 1))?;
        if fields.next().is_some() || key != expected_key || value.is_empty() {
            return Err(eyre!(
                "release prebuilt manifest row {} must be the unique non-empty `{expected_key}` \
                 field",
                index + 1
            ));
        }
        values.push(value);
    }
    if values[0] != SUMERAGI_PREBUILT_MANIFEST_SCHEMA_VERSION {
        return Err(eyre!(
            "unsupported release prebuilt manifest schema version {}",
            values[0]
        ));
    }
    if values[1] != source_manifest_sha256 {
        return Err(eyre!(
            "release prebuilt manifest source digest does not match inherited release identity"
        ));
    }
    for (value, label) in [
        (values[2], "release manifest Cargo.lock digest"),
        (values[3], "release manifest Cargo version digest"),
        (values[4], "release manifest rustc version digest"),
    ] {
        if !is_lowercase_sha256(value) {
            return Err(eyre!("{label} must be a lowercase SHA-256 digest"));
        }
    }
    let current_lock_sha256 = hash_workspace_cargo_lock(repo)?;
    if values[2] != current_lock_sha256 {
        return Err(eyre!(
            "release prebuilt manifest Cargo.lock digest does not match the current workspace"
        ));
    }
    if let Some(inherited_lock) = exact_env_value(IROHA_RELEASE_CARGO_LOCK_SHA256_ENV)? {
        if !is_lowercase_sha256(&inherited_lock) || values[2] != inherited_lock {
            return Err(eyre!(
                "release prebuilt manifest Cargo.lock digest does not match \
                 {IROHA_RELEASE_CARGO_LOCK_SHA256_ENV}"
            ));
        }
    }
    validate_target_triple(values[5], "release manifest host triple")?;
    validate_target_triple(values[6], "release manifest target triple")?;
    if values[7] != "release" {
        return Err(eyre!(
            "release prebuilt manifest profile must be exactly `release`"
        ));
    }
    for env_key in [IROHA_TEST_BUILD_PROFILE_ENV, "PROFILE"] {
        if let Some(profile) = exact_env_value(env_key)?
            && profile != "release"
        {
            return Err(eyre!(
                "release binary resolution requires {env_key}=release; got {profile:?}"
            ));
        }
    }
    let configured_target_text = configured_target.to_str().ok_or_else(|| {
        eyre!("release invocation bundle path must contain valid Unicode for manifest binding")
    })?;
    if values[8] != configured_target_text {
        return Err(eyre!(
            "release prebuilt manifest bundle_dir does not match {IROHA_TEST_TARGET_DIR_ENV}"
        ));
    }
    let mut binaries = Vec::with_capacity(ReleasePrebuiltBinary::ALL.len());
    for (ordinal, kind) in ReleasePrebuiltBinary::ALL.into_iter().enumerate() {
        let base = BASE_FIELD_COUNT + ordinal * 4;
        if values[base] != kind.relative_path() {
            return Err(eyre!(
                "release prebuilt manifest `{}` path must be exactly `{}`",
                kind.manifest_prefix(),
                kind.relative_path()
            ));
        }
        if !is_lowercase_sha256(values[base + 1]) {
            return Err(eyre!(
                "release prebuilt manifest `{}` digest must be lowercase SHA-256",
                kind.manifest_prefix()
            ));
        }
        let size_bytes = parse_canonical_size(
            values[base + 2],
            &format!(
                "release prebuilt manifest `{}` size",
                kind.manifest_prefix()
            ),
        )?;
        if size_bytes == 0 || size_bytes > MAX_SUMERAGI_PREBUILT_BINARY_BYTES {
            return Err(eyre!(
                "release prebuilt manifest `{}` size must be within 1..={}",
                kind.manifest_prefix(),
                MAX_SUMERAGI_PREBUILT_BINARY_BYTES
            ));
        }
        if values[base + 3] != RELEASE_BINARY_MODE_OCTAL {
            return Err(eyre!(
                "release prebuilt manifest `{}` mode must be exactly {RELEASE_BINARY_MODE_OCTAL}",
                kind.manifest_prefix()
            ));
        }
        binaries.push(ReleaseBinaryAttestation {
            kind,
            sha256: values[base + 1].to_owned(),
            size_bytes,
        });
    }
    binaries.try_into().map_err(|_| {
        eyre!("release prebuilt manifest must contain exactly four executable attestations")
    })
}
fn release_program_contract(repo: &Path) -> color_eyre::Result<Option<ReleaseProgramContract>> {
    let source_manifest_sha256 = exact_env_value(IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV)?;
    let prebuilt_manifest_sha256 = exact_env_value(IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV)?;
    let Some(source_manifest_sha256) = source_manifest_sha256 else {
        if prebuilt_manifest_sha256.is_some() {
            return Err(eyre!(
                "{IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV} requires \
                 {IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV}"
            ));
        }
        return Ok(None);
    };
    if !is_lowercase_sha256(&source_manifest_sha256) {
        return Err(eyre!(
            "{IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV} must be a lowercase SHA-256 digest"
        ));
    }
    let prebuilt_manifest_sha256 = prebuilt_manifest_sha256.ok_or_else(|| {
        eyre!(
            "release binary resolution requires inherited \
             {IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV}"
        )
    })?;
    if !is_lowercase_sha256(&prebuilt_manifest_sha256) {
        return Err(eyre!(
            "{IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV} must be a lowercase SHA-256 digest"
        ));
    }
    if exact_env_value(IROHA_TEST_SKIP_BUILD_ENV)?.as_deref() != Some("1") {
        return Err(eyre!(
            "release binary resolution requires {IROHA_TEST_SKIP_BUILD_ENV}=1 after the \
             top-level prebuild"
        ));
    }
    let configured_target_raw = exact_env_value(IROHA_TEST_TARGET_DIR_ENV)?.ok_or_else(|| {
        eyre!(
            "release binary resolution requires {IROHA_TEST_TARGET_DIR_ENV} to select the \
             manifest-addressed top-level prebuild"
        )
    })?;
    let configured_target = PathBuf::from(&configured_target_raw);
    if !configured_target.is_absolute() {
        return Err(eyre!(
            "release binary resolution requires an absolute {IROHA_TEST_TARGET_DIR_ENV}"
        ));
    }
    let artifact_root_raw = exact_env_value(IROHA_RELEASE_ARTIFACT_ROOT_ENV)?.ok_or_else(|| {
        eyre!("release binary resolution requires inherited {IROHA_RELEASE_ARTIFACT_ROOT_ENV}")
    })?;
    let artifact_root = authenticate_release_artifact_root(repo, &artifact_root_raw)?;
    let expected_programs_root = artifact_root
        .join(SUMERAGI_RELEASE_TARGET_SUBDIR)
        .join(&source_manifest_sha256)
        .join(SUMERAGI_RELEASE_PROGRAMS_SUBDIR);
    if configured_target.parent() != Some(expected_programs_root.as_path()) {
        return Err(eyre!(
            "{IROHA_TEST_TARGET_DIR_ENV} must be an immediate private invocation bundle under {}; \
             got {}",
            expected_programs_root.display(),
            configured_target.display()
        ));
    }
    let _invocation_suffix = configured_target
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(SUMERAGI_RELEASE_INVOCATION_PREFIX))
        .filter(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .ok_or_else(|| {
            eyre!(
                "{IROHA_TEST_TARGET_DIR_ENV} private bundle name must be `{}` followed by a \
                 non-empty ASCII alphanumeric token",
                SUMERAGI_RELEASE_INVOCATION_PREFIX
            )
        })?;
    published_directory_metadata(
        &configured_target,
        RELEASE_BINARY_MODE,
        "release invocation bundle",
    )?;
    let canonical_target_dir = configured_target.canonicalize().wrap_err_with(|| {
        eyre!(
            "release program target {} is missing; prebuild all corridor binaries at the \
             top level before setting {IROHA_TEST_SKIP_BUILD_ENV}=1",
            configured_target.display()
        )
    })?;
    let canonical_expected_programs_root =
        expected_programs_root.canonicalize().wrap_err_with(|| {
            eyre!(
                "failed to canonicalize manifest-addressed release programs root {}",
                expected_programs_root.display()
            )
        })?;
    if canonical_expected_programs_root != expected_programs_root {
        return Err(eyre!(
            "manifest-addressed release programs root must contain no symlinked or non-canonical components"
        ));
    }
    if canonical_target_dir.parent() != Some(canonical_expected_programs_root.as_path()) {
        return Err(eyre!(
            "{IROHA_TEST_TARGET_DIR_ENV} resolves outside the manifest-addressed release target"
        ));
    }
    let manifest_path = configured_target.join(SUMERAGI_PREBUILT_MANIFEST);
    let manifest_bytes = read_release_manifest(&manifest_path)?;
    let observed_manifest_sha256 = lowercase_hex(&sha256(&manifest_bytes));
    if observed_manifest_sha256 != prebuilt_manifest_sha256 {
        return Err(eyre!(
            "release prebuilt manifest digest does not match inherited \
             {IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV}"
        ));
    }
    let binaries = parse_release_prebuilt_manifest(
        &manifest_bytes,
        &source_manifest_sha256,
        &configured_target,
        repo,
    )?;
    Ok(Some(ReleaseProgramContract {
        configured_target_dir: configured_target,
        canonical_target_dir,
        binaries,
    }))
}
fn validate_release_program_candidate(
    contract: &ReleaseProgramContract,
    kind: ReleasePrebuiltBinary,
    candidate: impl AsRef<Path>,
) -> color_eyre::Result<PathBuf> {
    let attestation = contract.binary(kind);
    let expected = contract.configured_target_dir.join(kind.relative_path());
    let expected_canonical = expected.canonicalize().wrap_err_with(|| {
        eyre!(
            "release `{}` binary {} is missing",
            kind.manifest_prefix(),
            expected.display()
        )
    })?;
    let candidate = candidate.as_ref();
    let candidate_canonical = candidate.canonicalize().wrap_err_with(|| {
        eyre!(
            "failed to canonicalize release `{}` binary {}",
            kind.manifest_prefix(),
            candidate.display()
        )
    })?;
    if candidate_canonical != expected_canonical {
        return Err(eyre!(
            "release `{}` binary path must be exactly {}; got {}",
            kind.manifest_prefix(),
            expected.display(),
            candidate.display()
        ));
    }
    let mut component_path = contract.configured_target_dir.clone();
    let relative = Path::new(kind.relative_path());
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        let Component::Normal(component) = component else {
            return Err(eyre!(
                "release `{}` manifest path is not canonical",
                kind.manifest_prefix()
            ));
        };
        component_path.push(component);
        if index + 1 < component_count {
            published_directory_metadata(
                &component_path,
                RELEASE_BINARY_MODE,
                "release binary parent directory",
            )?;
        }
    }
    let before =
        published_regular_file_metadata(&expected, RELEASE_BINARY_MODE, kind.manifest_prefix())?;
    if before.len() != attestation.size_bytes {
        return Err(eyre!(
            "release `{}` binary size mismatch: expected {}, got {}",
            kind.manifest_prefix(),
            attestation.size_bytes,
            before.len()
        ));
    }
    let file = fs::File::open(&expected).wrap_err_with(|| {
        eyre!(
            "failed to open release `{}` binary {}",
            kind.manifest_prefix(),
            expected.display()
        )
    })?;
    let opened = file.metadata().wrap_err_with(|| {
        eyre!(
            "failed to inspect opened release `{}` binary",
            kind.manifest_prefix()
        )
    })?;
    if !same_file_identity(&before, &opened) {
        return Err(eyre!(
            "release `{}` binary changed while it was being opened",
            kind.manifest_prefix()
        ));
    }
    let (digest, size) = sha256_reader_bounded(file, MAX_SUMERAGI_PREBUILT_BINARY_BYTES)
        .wrap_err_with(|| {
            eyre!(
                "failed to hash bounded release `{}` binary",
                kind.manifest_prefix()
            )
        })?;
    let after =
        published_regular_file_metadata(&expected, RELEASE_BINARY_MODE, kind.manifest_prefix())?;
    if size != attestation.size_bytes || !same_file_identity(&opened, &after) {
        return Err(eyre!(
            "release `{}` binary changed while it was being hashed",
            kind.manifest_prefix()
        ));
    }
    if lowercase_hex(&digest) != attestation.sha256 {
        return Err(eyre!(
            "release `{}` binary SHA-256 does not match the prebuilt manifest",
            kind.manifest_prefix()
        ));
    }
    if !candidate_canonical.starts_with(&contract.canonical_target_dir) {
        return Err(eyre!(
            "release `{}` binary escaped the private invocation bundle",
            kind.manifest_prefix()
        ));
    }
    Ok(candidate_canonical)
}
/// Resolve and independently verify one binary from an active release prebuild contract.
///
/// `Ok(None)` means no source-bound release contract is active.
#[doc(hidden)]
pub fn resolve_release_prebuilt_binary(
    kind: ReleasePrebuiltBinary,
) -> color_eyre::Result<Option<PathBuf>> {
    let Some(contract) = release_program_contract(&compiled_repo_path())? else {
        return Ok(None);
    };
    validate_release_program_candidate(
        &contract,
        kind,
        contract.configured_target_dir.join(kind.relative_path()),
    )
    .map(Some)
}
/// Revalidate a previously resolved release binary against fresh manifest and file evidence.
///
/// `Ok(None)` means no source-bound release contract is active.
#[doc(hidden)]
pub fn revalidate_release_prebuilt_binary(
    kind: ReleasePrebuiltBinary,
    candidate: impl AsRef<Path>,
) -> color_eyre::Result<Option<PathBuf>> {
    let Some(contract) = release_program_contract(&compiled_repo_path())? else {
        return Ok(None);
    };
    validate_release_program_candidate(&contract, kind, candidate).map(Some)
}
fn profile_hint_from_exe_path(current_exe: &Path) -> Option<String> {
    let mut dir = current_exe.parent()?;
    if dir.file_name().is_some_and(|value| value == "deps") {
        dir = dir.parent()?;
    }
    let profile = dir.file_name()?.to_str()?.trim();
    if profile.is_empty() {
        None
    } else {
        Some(profile.to_owned())
    }
}
fn current_exe_profile_hint() -> Option<String> {
    let current_exe = std::env::current_exe().ok()?;
    profile_hint_from_exe_path(&current_exe)
}
fn default_build_profile() -> String {
    if let Ok(profile) = std::env::var(IROHA_TEST_BUILD_PROFILE_ENV) {
        return profile;
    }
    if let Ok(profile) = std::env::var("PROFILE") {
        return profile;
    }
    current_exe_profile_hint().unwrap_or_else(|| "release".to_string())
}
fn first_existing_candidate<'a>(
    candidates: impl IntoIterator<Item = Cow<'a, Path>>,
) -> Option<PathBuf> {
    for candidate in candidates {
        if let Ok(resolved) = candidate.as_ref().canonicalize() {
            return Some(resolved);
        }
    }
    None
}
fn colocated_binary_candidate_for(current_exe: &Path, bin: &str) -> Option<PathBuf> {
    let current_dir = current_exe.parent()?;
    current_dir.join(bin).canonicalize().ok()
}
fn current_exe_colocated_binary(bin: &str) -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    colocated_binary_candidate_for(&current_exe, bin)
}
fn build_cache_dir(target_dir: &Path) -> PathBuf {
    target_dir.join(BUILD_CACHE_DIR)
}
fn stamp_path(cache_dir: &Path, pkg: &str, profile: &str) -> PathBuf {
    cache_dir.join(format!("{pkg}-{profile}.json"))
}
fn lock_path(cache_dir: &Path, pkg: &str, profile: &str) -> PathBuf {
    cache_dir.join(format!("{pkg}-{profile}.lock"))
}
fn global_build_lock_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("cargo-build.lock")
}
fn is_rustc_metadata_mismatch(output: &str) -> bool {
    // Top-level builds occasionally trip over stale/corrupted `target` artifacts (e.g. after
    // toolchain upgrades or interrupted builds). Cleaning the target dir and retrying once is a
    // pragmatic recovery strategy.
    //
    // E0460: compiled by a different rustc / incompatible metadata.
    // E0463: dependencies are "missing" (often because their artifacts vanished or are corrupted).
    output.contains("E0460")
        || output.contains("rustc --explain E0460")
        || output.contains("E0463")
        || output.contains("rustc --explain E0463")
        || output.contains("can't find crate for `")
}
fn clean_target_dir_preserving_build_cache(target_dir: &Path) -> color_eyre::Result<()> {
    if !target_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(target_dir).wrap_err_with(|| {
        eyre!(
            "Failed to list target dir for cleanup: {}",
            target_dir.display()
        )
    })? {
        let entry = entry?;
        if entry.file_name().as_os_str() == std::ffi::OsStr::new(BUILD_CACHE_DIR) {
            continue;
        }
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            fs::remove_dir_all(&path).wrap_err_with(|| {
                eyre!(
                    "Failed to remove target dir entry during cleanup: {}",
                    path.display()
                )
            })?;
        } else {
            fs::remove_file(&path).wrap_err_with(|| {
                eyre!(
                    "Failed to remove target file entry during cleanup: {}",
                    path.display()
                )
            })?;
        }
    }
    Ok(())
}
#[derive(Debug, Default)]
struct IgnoreList {
    dirs: HashSet<PathBuf>,
    files: HashSet<PathBuf>,
    globs: Vec<IgnorePattern>,
}
#[derive(Debug)]
struct IgnorePattern {
    pattern: String,
    dir_only: bool,
    match_basename: bool,
}
fn read_build_stamp(path: &Path) -> color_eyre::Result<Option<BuildStamp>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents =
        fs::read_to_string(path).wrap_err_with(|| eyre!("Failed to read stamp file {path:?}"))?;
    let value = json::from_str(&contents)
        .wrap_err_with(|| eyre!("Failed to parse stamp file at {path:?}"))?;
    let JsonValue::Object(map) = value else {
        return Ok(None);
    };
    let version = map.get("version").and_then(JsonValue::as_u64).unwrap_or(0);
    if version != u64::from(BUILD_STAMP_VERSION) {
        return Ok(None);
    }
    let fingerprint = match map.get("fingerprint").and_then(JsonValue::as_u64) {
        Some(val) => val,
        None => return Ok(None),
    };
    let profile = match map.get("profile").and_then(JsonValue::as_str) {
        Some(val) => val.to_owned(),
        None => return Ok(None),
    };
    let binary = match map.get("binary").and_then(JsonValue::as_str) {
        Some(val) => PathBuf::from(val),
        None => return Ok(None),
    };
    Ok(Some(BuildStamp {
        fingerprint,
        profile,
        binary,
    }))
}
fn write_build_stamp(path: &Path, stamp: &BuildStamp) -> color_eyre::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| eyre!("Failed to create stamp directory {parent:?}"))?;
    }
    let mut object = json::Map::new();
    object.insert(
        "version".to_string(),
        json::to_value(&BUILD_STAMP_VERSION).wrap_err("encode stamp version")?,
    );
    object.insert(
        "fingerprint".to_string(),
        json::to_value(&stamp.fingerprint).wrap_err("encode stamp fingerprint")?,
    );
    object.insert(
        "profile".to_string(),
        JsonValue::String(stamp.profile.clone()),
    );
    object.insert(
        "binary".to_string(),
        JsonValue::String(stamp.binary.to_string_lossy().to_string()),
    );
    let value = JsonValue::Object(object);
    let rendered = json::to_string(&value).wrap_err("Failed to render stamp JSON")?;
    fs::write(path, rendered).wrap_err_with(|| eyre!("Failed to write stamp file {path:?}"))?;
    Ok(())
}
fn load_ignore_list(root: &Path) -> IgnoreList {
    let mut list = IgnoreList::default();
    let gitignore = root.join(".gitignore");
    let Ok(contents) = fs::read_to_string(gitignore) else {
        return list;
    };
    for raw_line in contents.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        let is_dir = trimmed.ends_with('/');
        let mut path_str = trimmed
            .trim_start_matches("./")
            .trim_end_matches('/')
            .trim();
        if let Some(stripped) = path_str.strip_prefix('/') {
            path_str = stripped;
        }
        if path_str.is_empty() {
            continue;
        }
        if path_str.contains('*') || path_str.contains('?') {
            list.globs.push(IgnorePattern {
                pattern: path_str.to_string(),
                dir_only: is_dir,
                match_basename: !path_str.contains('/'),
            });
            continue;
        }
        let path = PathBuf::from(path_str);
        if is_dir {
            list.dirs.insert(path);
        } else {
            list.files.insert(path);
        }
    }
    list
}
fn should_ignore_path(rel: &Path, ignore: &IgnoreList, is_dir: bool) -> bool {
    if rel.as_os_str().is_empty() {
        return false;
    }
    if is_dir {
        for ignored in &ignore.dirs {
            if rel == ignored || rel.starts_with(ignored) {
                return true;
            }
        }
    }
    if !is_dir && ignore.files.contains(rel) {
        return true;
    }
    for ignored in &ignore.dirs {
        if rel.starts_with(ignored) {
            return true;
        }
    }
    if ignore.globs.is_empty() {
        return false;
    }
    let rel_str = normalize_rel_path(rel);
    let name = rel
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_else(|| Cow::Borrowed(""));
    for pattern in &ignore.globs {
        if pattern.dir_only && !is_dir {
            continue;
        }
        let text = if pattern.match_basename {
            name.as_ref()
        } else {
            rel_str.as_str()
        };
        if glob_match(&pattern.pattern, text) {
            return true;
        }
    }
    false
}
fn normalize_rel_path(rel: &Path) -> String {
    let mut out = String::new();
    for component in rel.components() {
        let Component::Normal(raw) = component else {
            continue;
        };
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&raw.to_string_lossy());
    }
    out
}
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut pi = 0;
    let mut ti = 0;
    let mut star = None;
    let mut star_match = 0;
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            star_match = ti;
        } else if let Some(star_pos) = star {
            star_match += 1;
            ti = star_match;
            pi = star_pos + 1;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}
fn add_target_dir_to_ignore(root: &Path, ignore: &mut IgnoreList) {
    fn push_dir(root: &Path, ignore: &mut IgnoreList, path: &Path) {
        if let Ok(relative) = path.strip_prefix(root)
            && !relative.as_os_str().is_empty()
        {
            ignore.dirs.insert(relative.to_path_buf());
        }
    }
    push_dir(root, ignore, &root.join("target"));
    if let Ok(path) = std::env::var("CARGO_TARGET_DIR") {
        let base = resolve_target_dir_path(root, &path);
        push_dir(root, ignore, &base);
        push_dir(root, ignore, &base.join(IROHA_TEST_TARGET_SUBDIR));
    }
    if let Ok(path) = std::env::var(IROHA_TEST_TARGET_DIR_ENV) {
        let custom = resolve_target_dir_path(root, &path);
        push_dir(root, ignore, &custom);
    }
    let target_dir = resolve_target_dir(root);
    push_dir(root, ignore, &target_dir);
}
fn workspace_members(root: &Path) -> color_eyre::Result<Vec<PathBuf>> {
    let manifest = root.join("Cargo.toml");
    let contents = fs::read_to_string(&manifest)
        .wrap_err_with(|| eyre!("Failed to read workspace manifest at {manifest:?}"))?;
    let parsed: toml::Value = toml::from_str(&contents)
        .wrap_err_with(|| eyre!("Failed to parse workspace manifest at {manifest:?}"))?;
    let Some(workspace) = parsed.get("workspace") else {
        return Ok(vec![]);
    };
    let Some(members) = workspace.get("members").and_then(|value| value.as_array()) else {
        return Ok(vec![]);
    };
    let mut out = Vec::new();
    for member in members {
        let Some(pattern) = member.as_str() else {
            continue;
        };
        out.extend(expand_workspace_member(root, pattern)?);
    }
    // Deduplicate while preserving order
    let mut seen = HashSet::new();
    out.retain(|path| seen.insert(path.clone()));
    Ok(out)
}
fn expand_workspace_member(root: &Path, pattern: &str) -> color_eyre::Result<Vec<PathBuf>> {
    if pattern.contains('*') {
        expand_workspace_pattern(root, pattern)
    } else {
        Ok(vec![root.join(pattern)])
    }
}
fn expand_workspace_pattern(root: &Path, pattern: &str) -> color_eyre::Result<Vec<PathBuf>> {
    let segments: Vec<&str> = pattern.split('/').collect();
    let mut results = Vec::new();
    fn recurse(
        root: &Path,
        current: &Path,
        segments: &[&str],
        index: usize,
        results: &mut Vec<PathBuf>,
    ) -> color_eyre::Result<()> {
        if index == segments.len() {
            if current.exists() {
                results.push(current.to_path_buf());
            }
            return Ok(());
        }
        let segment = segments[index];
        if segment.is_empty() {
            return recurse(root, current, segments, index + 1, results);
        }
        if segment == "*" {
            if !current.exists() {
                return Ok(());
            }
            for entry in fs::read_dir(current)
                .wrap_err_with(|| eyre!("Failed to expand workspace glob at {current:?}"))?
            {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    recurse(root, &entry.path(), segments, index + 1, results)?;
                }
            }
            return Ok(());
        }
        let next = if current == root {
            root.join(segment)
        } else {
            current.join(segment)
        };
        recurse(root, &next, segments, index + 1, results)
    }
    recurse(root, root, &segments, 0, &mut results)?;
    Ok(results)
}
fn hash_file_entry(root: &Path, path: &Path, metadata: &fs::Metadata, hasher: &mut DefaultHasher) {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().hash(hasher);
    metadata.len().hash(hasher);
    if let Ok(modified) = metadata.modified() {
        match modified.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                duration.as_secs().hash(hasher);
                duration.subsec_nanos().hash(hasher);
            }
            Err(_) => {
                // Ignore files with pre-epoch timestamps (unlikely on supported filesystems)
            }
        }
    }
}
fn hash_file_if_exists(
    workspace_root: &Path,
    path: &Path,
    hasher: &mut DefaultHasher,
) -> color_eyre::Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            hash_file_entry(workspace_root, path, &metadata, hasher);
        }
        Ok(_) => {}
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err).wrap_err_with(|| eyre!("Failed to read metadata for {path:?}"));
            }
        }
    }
    Ok(())
}
fn hash_member_dir(
    workspace_root: &Path,
    member_dir: &Path,
    ignore: &IgnoreList,
    hasher: &mut DefaultHasher,
) -> color_eyre::Result<()> {
    if !member_dir.exists() {
        return Ok(());
    }
    let mut stack = vec![member_dir.to_path_buf()];
    let mut visited = HashSet::new();
    while let Some(dir) = stack.pop() {
        if !dir.exists() {
            continue;
        }
        let Ok(relative_dir) = dir.strip_prefix(workspace_root) else {
            continue;
        };
        if !visited.insert(relative_dir.to_path_buf()) {
            continue;
        }
        if should_ignore_path(relative_dir, ignore, true) || should_skip_dir(&dir) {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(iter) => iter,
            Err(err) => {
                if dir == member_dir {
                    return Err(err)
                        .wrap_err_with(|| eyre!("Failed to read workspace member at {dir:?}"));
                }
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            let Ok(relative_path) = path.strip_prefix(workspace_root) else {
                continue;
            };
            if file_type.is_dir() {
                if should_ignore_path(relative_path, ignore, true) || should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() {
                if should_ignore_path(relative_path, ignore, false) || should_skip_file(&path) {
                    continue;
                }
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                hash_file_entry(workspace_root, &path, &metadata, hasher);
            }
        }
    }
    Ok(())
}
fn should_skip_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(
        name,
        "target"
            | ".git"
            | ".hg"
            | ".svn"
            | ".idea"
            | ".vscode"
            | ".cargo"
            | "node_modules"
            | ".venv"
            | "venv"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | "__pycache__"
            | "coverage"
            | "dist"
            | "tmp"
    )
}
fn should_skip_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(name, ".DS_Store" | "Thumbs.db")
}
fn workspace_fingerprint(root: &Path) -> color_eyre::Result<u64> {
    let mut hasher = DefaultHasher::new();
    let mut ignore = load_ignore_list(root);
    add_target_dir_to_ignore(root, &mut ignore);
    let members = workspace_members(root)?;
    hash_file_if_exists(root, &root.join("Cargo.toml"), &mut hasher)?;
    hash_file_if_exists(root, &root.join("Cargo.lock"), &mut hasher)?;
    hash_file_if_exists(root, &root.join("rust-toolchain.toml"), &mut hasher)?;
    hash_file_if_exists(root, &root.join("rust-toolchain"), &mut hasher)?;
    if members.is_empty() {
        hash_member_dir(root, root, &ignore, &mut hasher)?;
    } else {
        for member in members {
            hash_member_dir(root, &member, &ignore, &mut hasher)?;
        }
    }
    Ok(hasher.finish())
}
fn fingerprint_with_build_args(base: u64, build_args: &[OsString]) -> u64 {
    let mut hasher = DefaultHasher::new();
    base.hash(&mut hasher);
    for arg in build_args {
        arg.hash(&mut hasher);
    }
    hasher.finish()
}
fn build_env_overrides() -> [(&'static str, &'static str); 2] {
    // Streaming runtime requires bundled rANS tables; compile test binaries with bundles enabled.
    // Developers may work with unsynced Norito bindings locally; skip the workspace-level
    // bindings check when building test binaries to avoid unrelated integration test failures.
    [
        ("ENABLE_RANS_BUNDLES", "1"),
        ("NORITO_SKIP_BINDINGS_SYNC", "1"),
    ]
}
fn cargo_or_rustc_processes(process_table: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(process_table)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?;
            let elapsed = fields.next()?;
            let executable = fields.next()?;
            let executable_name = Path::new(executable).file_name()?.to_string_lossy();
            matches!(
                executable_name.as_ref(),
                "cargo" | "cargo.exe" | "rustc" | "rustc.exe"
            )
            .then(|| format!("pid={pid},etime={elapsed},program={executable}"))
        })
        .collect()
}
fn ensure_child_cargo_quiescent(cargo_program: &str) -> color_eyre::Result<()> {
    let cargo_program_name = Path::new(cargo_program)
        .file_name()
        .map(|name| name.to_string_lossy());
    if cfg!(test)
        && !cargo_program_name
            .as_deref()
            .is_some_and(|name| matches!(name, "cargo" | "cargo.exe"))
    {
        // Unit tests use a non-Cargo fixture script to validate command construction and retries.
        return Ok(());
    }
    let output = std::process::Command::new("ps")
        .args(["-axo", "pid,etime,command"])
        .output()
        .wrap_err("failed to run exact Cargo/rustc process quiescence check")?;
    if !output.status.success() {
        return Err(eyre!(
            "`ps -axo pid,etime,command` failed before child Cargo invocation: {:?}",
            output.status.code()
        ));
    }
    let active = cargo_or_rustc_processes(&output.stdout);
    if !active.is_empty() {
        return Err(eyre!(
            "refusing child Cargo invocation while Cargo/rustc is active; prebuild at the top \
             level instead: {}",
            active.join("; ")
        ));
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)] // Helper aggregates build context parameters.
fn ensure_binary_fresh(
    repo: &Path,
    pkg: &str,
    name: &str,
    target_dir: &Path,
    profile: &str,
    binary_path: &Path,
    allow_build: bool,
    build_args: &[OsString],
) -> color_eyre::Result<()> {
    let cache_dir = build_cache_dir(target_dir);
    fs::create_dir_all(&cache_dir)
        .wrap_err_with(|| eyre!("Failed to prepare build cache directory {cache_dir:?}"))?;
    let stamp_path = stamp_path(&cache_dir, pkg, profile);
    let lock_path = lock_path(&cache_dir, pkg, profile);
    let mut lock = LockFile::open(&lock_path)
        .wrap_err_with(|| eyre!("Failed to open build lock at {lock_path:?}"))?;
    lock.lock()
        .wrap_err_with(|| eyre!("Failed to acquire build lock for {pkg}"))?;
    let mut fingerprint = workspace_fingerprint(repo)?;
    fingerprint = fingerprint_with_build_args(fingerprint, build_args);
    let stamp = read_build_stamp(&stamp_path)?;
    let mut needs_build = !binary_path.exists();
    if !needs_build {
        match &stamp {
            Some(prev) if prev.fingerprint == fingerprint && prev.profile == profile => {
                // Binary is present and fingerprint matches; reuse existing build.
            }
            _ => needs_build = true,
        }
    }
    if needs_build && !allow_build {
        return Err(eyre!(
            "cannot build `{name}` (pkg `{pkg}`) because automatic child builds are disabled; \
             build it ahead of time with `cargo build --locked --offline -p {pkg}` and rerun \
             with {IROHA_TEST_SKIP_BUILD_ENV}=1; target_dir={}",
            target_dir.display()
        ));
    }
    if needs_build {
        tracing::info!(%name, %pkg, %profile, "building `{name}` for tests");
        let build_lock_path = global_build_lock_path(&cache_dir);
        let mut build_lock = LockFile::open(&build_lock_path)
            .wrap_err_with(|| eyre!("Failed to open build lock at {build_lock_path:?}"))?;
        build_lock
            .lock()
            .wrap_err_with(|| eyre!("Failed to acquire global build lock for {pkg}"))?;
        let cargo_program =
            std::env::var("TEST_NETWORK_CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let mut attempt = 0_u8;
        loop {
            attempt = attempt.saturating_add(1);
            let mut command = std::process::Command::new(&cargo_program);
            command
                .arg("build")
                .arg("--locked")
                .arg("--offline")
                .arg("-p")
                .arg(pkg);
            match profile {
                "debug" => {}
                "release" => {
                    command.arg("--release");
                }
                other => {
                    command.arg("--profile").arg(other);
                }
            }
            for arg in build_args {
                command.arg(arg);
            }
            command.env("CARGO_TARGET_DIR", target_dir);
            for (key, value) in build_env_overrides() {
                command.env(key, value);
            }
            command.current_dir(repo);
            ensure_child_cargo_quiescent(&cargo_program)?;
            let output = command_output_with_timeout(&mut command, build_command_timeout_env())
                .wrap_err("failed to invoke cargo to build binary")?;
            if output.status.success() {
                break;
            }
            let code = output.status.code();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = format!("{stdout}\n{stderr}");
            if attempt == 1 && is_rustc_metadata_mismatch(&combined) {
                warn!(
                    %name,
                    %pkg,
                    %profile,
                    target_dir = %target_dir.display(),
                    "detected stale/corrupted build artifacts; cleaning target dir and retrying build"
                );
                clean_target_dir_preserving_build_cache(target_dir)?;
                continue;
            }
            tracing::warn!(?code, build_stdout = %stdout, build_stderr = %stderr, "`cargo build` returned non-zero status");
            let err = eyre!(
                "failed to build `{name}` (pkg `{pkg}`), cargo status: {code:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            );
            let _ = build_lock.unlock();
            return Err(err);
        }
        // Refresh fingerprint after the successful build to capture generated files.
        fingerprint = workspace_fingerprint(repo)?;
        fingerprint = fingerprint_with_build_args(fingerprint, build_args);
        build_lock
            .unlock()
            .wrap_err_with(|| eyre!("Failed to release global build lock for {pkg}"))?;
    }
    if binary_path.exists() {
        let stamp = BuildStamp {
            fingerprint,
            profile: profile.to_owned(),
            binary: binary_path.to_path_buf(),
        };
        write_build_stamp(&stamp_path, &stamp)?;
    }
    lock.unlock()
        .wrap_err_with(|| eyre!("Failed to release build lock for {pkg}"))?;
    Ok(())
}
const fn child_build_allowed(running_under_cargo: bool, release_corridor: bool) -> bool {
    !running_under_cargo && !release_corridor
}
const fn must_validate_binary_freshness(skip_build: bool, allow_child_build: bool) -> bool {
    !skip_build && allow_child_build
}
fn cached_binary_if_present(cache: &OnceLock<PathBuf>) -> Option<PathBuf> {
    let cached = cache.get()?;
    if cached.exists() {
        return Some(cached.clone());
    }
    warn!(
        binary = %cached.display(),
        "cached program path is missing; resolving again"
    );
    None
}
impl Program {
    /// Resolve program path.
    ///
    /// Tries, in order:
    /// - Explicit env override (`TEST_NETWORK_BIN_*`).
    /// - `CARGO_BIN_EXE_*` if Cargo provided a direct path to the built binary
    /// - Common target locations (debug/release) under the repo root (defaulting to
    ///   `target/iroha-test-network`, or under `IROHA_TEST_TARGET_DIR` / `CARGO_TARGET_DIR` when set)
    /// - Rebuilds with `cargo build --locked --offline -p <pkg>` when the cached fingerprint
    ///   disagrees with the current workspace state (skipped when `IROHA_TEST_SKIP_BUILD=1`).
    ///
    /// A source-manifest-bound release corridor is lookup-only: it requires the top-level runner
    /// to prebuild into the manifest-addressed release target and skip child builds. Any resolver
    /// running under Cargo is likewise lookup-only; nested Cargo invocation is never supported.
    ///
    /// # Errors
    /// If the path is not found (and build did not help).
    fn resolve_internal(&self, skip_build_override: Option<bool>) -> color_eyre::Result<PathBuf> {
        self.resolve_internal_in_repo(skip_build_override, &compiled_repo_path())
    }

    fn resolve_internal_in_repo(
        &self,
        skip_build_override: Option<bool>,
        repo: &Path,
    ) -> color_eyre::Result<PathBuf> {
        fn bin_name(raw: &str) -> String {
            if cfg!(windows) {
                format!("{raw}.exe")
            } else {
                raw.to_owned()
            }
        }
        let ProgramSpec {
            name,
            env,
            pkg,
            build_args,
            isolated_target_subdir,
        } = self.spec();
        let release_contract = release_program_contract(repo)?;
        if release_contract.is_some() && !self.release_prebuilt_allowed() {
            return Err(eyre!(
                "feature-isolated test programs are forbidden in release-prebuilt corridors"
            ));
        }
        let release_binary = self.release_prebuilt_binary();
        // 1) Explicit override
        if let Ok(path) = std::env::var(env) {
            let raw = PathBuf::from(&path);
            let candidate = if raw.is_absolute() {
                raw
            } else {
                repo.join(raw)
            };
            let candidate = candidate
                .canonicalize()
                .wrap_err_with(|| eyre!("Used path from {env}: {path}"))
                .wrap_err_with(|| {
                    eyre!("Could not resolve path of `{name}` program. Have you built it?")
                })?;
            return match release_contract.as_ref() {
                Some(contract) => {
                    { validate_release_program_candidate(contract, release_binary, candidate) }
                        .wrap_err_with(|| {
                            eyre!(
                                "{env} must equal the exact manifest-attested release binary path"
                            )
                        })
                }
                None => Ok(candidate),
            };
        }
        // Explicit absolute prebuilt paths do not need the build checkout. Discovery
        // and freshness checks still require the real source repository.
        let canonical_repo = repo.canonicalize().wrap_err_with(|| {
            eyre!(
                "Could not access repository {} to discover or build `{name}`; provide an absolute `{env}` for a prebuilt diagnostic binary",
                repo.display()
            )
        })?;
        let repo = canonical_repo.as_path();
        // Fast path via cache (only when no override is present)
        let cached = match self {
            Program::Irohad => cached_binary_if_present(&IROHAD_BIN),
            Program::IrohadTaira => cached_binary_if_present(&IROHAD_TAIRA_BIN),
            Program::IrohadPrivateSettlementRoutes => {
                cached_binary_if_present(&IROHAD_PRIVATE_SETTLEMENT_ROUTES_BIN)
            }
            Program::IrohadParliamentSigners => {
                cached_binary_if_present(&IROHAD_PARLIAMENT_SIGNERS_BIN)
            }
            Program::IrohadDisposableBroker => {
                cached_binary_if_present(&IROHAD_DISPOSABLE_BROKER_BIN)
            }
            Program::Iroha => cached_binary_if_present(&IROHA_BIN),
        };
        if let Some(path) = cached {
            return match release_contract.as_ref() {
                Some(contract) => {
                    validate_release_program_candidate(contract, release_binary, path)
                }
                None => Ok(path),
            };
        }
        let bin = bin_name(name);
        // 2) Prefer paths Cargo already built (`CARGO_BIN_EXE_*`) but still allow rebuilds
        let cargo_bin_env = format!("CARGO_BIN_EXE_{name}");
        let allow_ambient_candidates =
            release_contract.is_none() && isolated_target_subdir.is_none();
        let cargo_bin_candidate = allow_ambient_candidates
            .then(|| {
                std::env::var(&cargo_bin_env)
                    .ok()
                    .and_then(|p| PathBuf::from(p).canonicalize().ok())
            })
            .flatten();
        let colocated_candidate = allow_ambient_candidates
            .then(|| current_exe_colocated_binary(&bin))
            .flatten();
        // 3) Prepare candidate locations under the current target directory
        let profile = default_build_profile();
        let target_dir = isolated_target_subdir.map_or_else(
            || resolve_target_dir(repo),
            |subdir| resolve_target_dir(repo).join(subdir),
        );
        let primary_binary = target_dir.join(format!("{profile}/{bin}"));
        let mut candidates: Vec<PathBuf> = Vec::new();
        let mut push_candidate = |path: PathBuf| {
            if !candidates.contains(&path) {
                candidates.push(path);
            }
        };
        if let Some(path) = cargo_bin_candidate {
            push_candidate(path);
        }
        if let Some(path) = colocated_candidate {
            push_candidate(path);
        }
        push_candidate(primary_binary.clone());
        push_candidate(target_dir.join(format!("debug/{bin}")));
        push_candidate(target_dir.join(format!("release/{bin}")));
        if release_contract.is_none() && isolated_target_subdir.is_none() {
            let default_target = repo.join("target");
            push_candidate(default_target.join(format!("{profile}/{bin}")));
            push_candidate(default_target.join(format!("debug/{bin}")));
            push_candidate(default_target.join(format!("release/{bin}")));
        }
        let prebuild_candidate =
            first_existing_candidate(candidates.iter().map(|p| Cow::Borrowed(p.as_path())));
        // 4) Decide whether to (re)build.
        //    We default to building to avoid using stale binaries across source changes.
        //    Set IROHA_TEST_SKIP_BUILD=1 to skip attempting a build.
        let skip_build = skip_build_override.unwrap_or_else(|| {
            std::env::var(IROHA_TEST_SKIP_BUILD_ENV)
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        });
        if release_contract.is_some() && !skip_build {
            return Err(eyre!(
                "release binary resolution cannot override {IROHA_TEST_SKIP_BUILD_ENV}=1"
            ));
        }
        let running_under_cargo = std::env::var_os("CARGO").is_some();
        let allow_child_build =
            child_build_allowed(running_under_cargo, release_contract.is_some());
        let validate_freshness = must_validate_binary_freshness(skip_build, allow_child_build);
        if !skip_build && !validate_freshness {
            if let Some(found) = prebuild_candidate.clone() {
                warn!(
                    %name,
                    %pkg,
                    ?found,
                    "child build forbidden under Cargo; using existing binary"
                );
                match self {
                    Program::Irohad => {
                        let _ = IROHAD_BIN.set(found.clone());
                    }
                    Program::IrohadPrivateSettlementRoutes => {
                        let _ = IROHAD_PRIVATE_SETTLEMENT_ROUTES_BIN.set(found.clone());
                    }
                    Program::IrohadTaira => {
                        let _ = IROHAD_TAIRA_BIN.set(found.clone());
                    }
                    Program::IrohadParliamentSigners => {
                        let _ = IROHAD_PARLIAMENT_SIGNERS_BIN.set(found.clone());
                    }
                    Program::IrohadDisposableBroker => {
                        let _ = IROHAD_DISPOSABLE_BROKER_BIN.set(found.clone());
                    }
                    Program::Iroha => {
                        let _ = IROHA_BIN.set(found.clone());
                    }
                }
                return Ok(found);
            }
        }
        if validate_freshness {
            ensure_binary_fresh(
                repo,
                pkg,
                name,
                &target_dir,
                &profile,
                &primary_binary,
                allow_child_build,
                &build_args,
            )?;
        }
        // 5) Return the best candidate after the (optional) build
        let post_build_candidates = if skip_build {
            first_existing_candidate(candidates.iter().map(|p| Cow::Borrowed(p.as_path())))
        } else {
            first_existing_candidate(
                iter::once(Cow::Borrowed(primary_binary.as_path()))
                    .chain(candidates.iter().map(|p| Cow::Borrowed(p.as_path()))),
            )
        };
        if let Some(found) = post_build_candidates {
            let found = match release_contract.as_ref() {
                Some(contract) => {
                    validate_release_program_candidate(contract, release_binary, found)?
                }
                None => found,
            };
            match self {
                Program::Irohad => {
                    let _ = IROHAD_BIN.set(found.clone());
                }
                Program::IrohadPrivateSettlementRoutes => {
                    let _ = IROHAD_PRIVATE_SETTLEMENT_ROUTES_BIN.set(found.clone());
                }
                Program::IrohadTaira => {
                    let _ = IROHAD_TAIRA_BIN.set(found.clone());
                }
                Program::IrohadParliamentSigners => {
                    let _ = IROHAD_PARLIAMENT_SIGNERS_BIN.set(found.clone());
                }
                Program::IrohadDisposableBroker => {
                    let _ = IROHAD_DISPOSABLE_BROKER_BIN.set(found.clone());
                }
                Program::Iroha => {
                    let _ = IROHA_BIN.set(found.clone());
                }
            }
            return Ok(found);
        }
        let candidates_txt = candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Err(eyre!(
            "Could not resolve path of `{name}` program. Have you built it?\n\
               Tried: {candidates_txt}\n  \
               Solutions:\n  \
               1. Run `cargo build --locked --offline -p {pkg}` in the guarded top-level \
                  prebuild\n  \
               2. Provide a different path via `{env}` env var"
        ))
    }
    pub fn resolve(&self) -> color_eyre::Result<PathBuf> {
        self.resolve_internal(None)
    }
    /// Async variant of [`Self::resolve`].
    ///
    /// Spawns a blocking task so that top-level builds and filesystem probing never block
    /// a Tokio runtime thread (which can otherwise starve timers and hang async tests).
    pub async fn resolve_async(&self) -> color_eyre::Result<PathBuf> {
        let program = *self;
        tokio::task::spawn_blocking(move || program.resolve_internal(None))
            .await
            .wrap_err("failed to join blocking task while resolving program")?
    }
    pub fn resolve_force_build(&self) -> color_eyre::Result<PathBuf> {
        self.resolve_internal(Some(false))
    }
    pub fn resolve_skip_build(&self) -> color_eyre::Result<PathBuf> {
        self.resolve_internal(Some(true))
    }
}
pub fn init_instruction_registry() {
    set_instruction_registry(iroha_data_model::instruction_registry::default());
}
impl Environment {
    /// Side effects:
    ///
    /// - Initialises logger (once)
    /// - Creates a temporary directory (keep: true)
    fn new() -> Self {
        init_logger_once();
        init_instruction_registry();
        let dir = generate_and_keep_temp_dir();
        Self { dir }
    }
}
#[derive(Debug)]
struct FilePermit {
    path: PathBuf,
}
impl Drop for FilePermit {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
struct NetworkPermit {
    _file_permit: FilePermit,
}
fn serialize_networks_enabled() -> bool {
    let Ok(raw) = std::env::var(SERIALIZE_NETWORKS_ENV) else {
        return false;
    };
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
fn network_parallelism_limit() -> usize {
    if serialize_networks_enabled() {
        return 1;
    }
    if let Ok(raw) = std::env::var(NETWORK_PARALLELISM_ENV)
        && let Ok(parsed) = raw.trim().parse::<usize>()
        && parsed > 0
    {
        return parsed;
    }
    DEFAULT_NETWORK_PARALLELISM_LIMIT
}
fn test_concurrency_threads() -> usize {
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    let networks = network_parallelism_limit().max(1);
    let peers = DEFAULT_NETWORK_PARALLELISM_PEERS.max(1);
    let total_peers = networks.saturating_mul(peers).max(1);
    let oversub = TEST_CONCURRENCY_OVERSUBSCRIPTION.max(1);
    let min_threads = cores.clamp(1, TEST_CONCURRENCY_MIN_THREADS);
    cores
        .saturating_mul(oversub)
        .saturating_div(total_peers)
        .max(min_threads)
}
fn permit_dir() -> PathBuf {
    if let Ok(path) = std::env::var(NETWORK_PERMIT_DIR_ENV) {
        return PathBuf::from(path);
    }
    default_permit_dir()
}
fn default_permit_dir() -> PathBuf {
    let mut dir = std::env::temp_dir().join("iroha_test_network_permits");
    if let Some(namespace) = default_permit_namespace() {
        dir.push(namespace);
    }
    dir
}
#[cfg(unix)]
fn default_permit_namespace() -> Option<String> {
    let parent = nix::unistd::getppid().as_raw();
    (parent > 0).then(|| format!("ppid-{parent}"))
}
#[cfg(not(unix))]
fn default_permit_namespace() -> Option<String> {
    None
}
fn network_permit_wait_timeout() -> Option<Duration> {
    let timeout = read_env_duration(
        NETWORK_PERMIT_WAIT_TIMEOUT_ENV,
        NETWORK_PERMIT_WAIT_TIMEOUT_DEFAULT,
    );
    (!timeout.is_zero()).then_some(timeout)
}
fn try_acquire_file_permit(limit: usize) -> Option<FilePermit> {
    let dir = permit_dir();
    try_acquire_file_permit_in(&dir, limit)
}
fn try_acquire_file_permit_in(dir: &Path, limit: usize) -> Option<FilePermit> {
    if limit == 0 {
        return None;
    }
    fs::create_dir_all(&dir).expect("failed to create network permit directory");
    let pid = std::process::id();
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    for slot in 0..limit {
        let path = dir.join(format!("permit-{slot}.lock"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let _ = writeln!(file, "pid={pid}");
                let _ = writeln!(file, "started={started}");
                return Some(FilePermit { path });
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                if permit_is_stale(&path) {
                    let _ = fs::remove_file(&path);
                    if let Ok(mut file) = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                    {
                        let _ = writeln!(file, "pid={pid}");
                        let _ = writeln!(file, "started={started}");
                        return Some(FilePermit { path });
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                let _ = fs::create_dir_all(&dir);
            }
            Err(_) => {}
        }
    }
    None
}
fn permit_is_stale(path: &Path) -> bool {
    if let Some(pid) = read_permit_pid(path)
        && let Some(alive) = pid_alive(pid)
    {
        return !alive;
    }
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age > NETWORK_PERMIT_STALE_TTL
}
fn read_permit_pid(path: &Path) -> Option<u32> {
    let contents = fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("pid=")
            && let Ok(pid) = value.trim().parse::<u32>()
            && pid > 0
        {
            return Some(pid);
        }
    }
    None
}
fn read_permit_started(path: &Path) -> Option<u64> {
    let contents = fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("started=")
            && let Ok(started) = value.trim().parse::<u64>()
            && started > 0
        {
            return Some(started);
        }
    }
    None
}
fn describe_permit_holders(limit: usize) -> String {
    let dir = permit_dir();
    let mut holders = Vec::new();
    for slot in 0..limit.max(1) {
        let path = dir.join(format!("permit-{slot}.lock"));
        if !path.exists() {
            continue;
        }
        let pid = read_permit_pid(&path)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        let alive = read_permit_pid(&path)
            .and_then(pid_alive)
            .map_or("unknown", |is_alive| if is_alive { "yes" } else { "no" });
        let started = read_permit_started(&path)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        holders.push(format!(
            "slot={slot},pid={pid},alive={alive},started={started},file={}",
            path.display()
        ));
    }
    if holders.is_empty() {
        "none".to_owned()
    } else {
        holders.join("; ")
    }
}
#[cfg(unix)]
fn pid_alive(pid: u32) -> Option<bool> {
    let raw_pid = i32::try_from(pid).ok()?;
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw_pid), None) {
        Ok(()) => Some(true),
        Err(nix::errno::Errno::EPERM) => Some(true),
        Err(nix::errno::Errno::ESRCH) => Some(false),
        Err(_) => None,
    }
}
#[cfg(not(unix))]
fn pid_alive(_pid: u32) -> Option<bool> {
    None
}
fn acquire_network_permit() -> NetworkPermit {
    let mut waited = Duration::ZERO;
    let mut next_log = NETWORK_PERMIT_LOG_INTERVAL;
    let wait_timeout = network_permit_wait_timeout();
    loop {
        let limit = network_parallelism_limit();
        if let Some(file_permit) = try_acquire_file_permit(limit) {
            return NetworkPermit {
                _file_permit: file_permit,
            };
        }
        if waited >= next_log {
            let dir = permit_dir();
            let holders = describe_permit_holders(limit);
            eprintln!(
                "waiting for test network permit: waited={waited:?} limit={limit} dir={} holders={holders}",
                dir.display()
            );
            info!(
                waited_ms = waited.as_millis(),
                limit, "waiting for test network permit"
            );
            next_log = next_log.saturating_add(NETWORK_PERMIT_LOG_INTERVAL);
        }
        if let Some(timeout) = wait_timeout
            && waited >= timeout
        {
            let dir = permit_dir();
            let holders = describe_permit_holders(limit);
            panic!(
                "timed out after {timeout:?} waiting for test network permit (limit={limit}, dir={}). holders={holders}. \
set {NETWORK_PERMIT_WAIT_TIMEOUT_ENV}=0 to disable timeout or provide an isolated \
{NETWORK_PERMIT_DIR_ENV} when running unrelated network suites concurrently",
                dir.display()
            );
        }
        std::thread::sleep(NETWORK_PERMIT_POLL_INTERVAL);
        waited = waited.saturating_add(NETWORK_PERMIT_POLL_INTERVAL);
    }
}
/// Immutable canonical genesis prepared before a peer cohort starts its timers.
#[derive(Clone)]
struct PreparedPeerGenesis {
    bytes: Arc<[u8]>,
    network_id: NetworkId,
}
impl PreparedPeerGenesis {
    async fn prepare(block: GenesisBlock) -> Result<Self> {
        Self::prepare_with_encoder(block, NetworkPeer::canonical_genesis_bytes).await
    }

    async fn prepare_optional(block: Option<&GenesisBlock>) -> Result<Option<Self>> {
        match block {
            Some(block) => Self::prepare(block.clone()).await.map(Some),
            None => Ok(None),
        }
    }

    // One blocking owner runs the canonical encoder and its existing sanity checks.
    // The injectable encoder keeps the ownership/async handoff test deterministic;
    // production callers always select `canonical_genesis_bytes` through `prepare`.
    async fn prepare_with_encoder(
        block: GenesisBlock,
        encode: impl FnOnce(&GenesisBlock) -> Result<Vec<u8>> + Send + 'static,
    ) -> Result<Self> {
        spawn_blocking(move || {
            init_instruction_registry();
            let network_id = NetworkId::from_genesis_hash(block.0.hash());
            encode(&block).map(|bytes| Self {
                bytes: bytes.into(),
                network_id,
            })
        })
        .await
        .wrap_err("failed to join canonical genesis preparation")?
    }
}

/// Network of peers
pub struct Network {
    env: Environment,
    // Keep this field as the validator roster: `peers()` predates observer
    // support and many consensus tests intentionally use its length as quorum
    // input.
    peers: Vec<NetworkPeer>,
    // Configured Validator processes that can serve participant-lane
    // committees but are excluded from the signed global roster.
    committee_validators: Vec<NetworkPeer>,
    observers: Vec<NetworkPeer>,
    observer_advertised_p2p_addresses: HashMap<PeerId, SocketAddr>,
    observer_slow_reader_relays: Option<ObserverSlowReaderRelays>,
    next_peer_index: AtomicUsize,
    block_cadence: Duration,
    block_sync_gossip_period: Duration,
    sync_timeout_override: Option<Duration>,
    peer_startup_timeout_override: Option<Duration>,
    consensus_profile: ConsensusBootstrapProfile,
    genesis_key_pair: KeyPair,
    genesis_isi: Vec<Vec<InstructionBox>>,
    genesis_post_topology_isi: Vec<Vec<InstructionBox>>,
    // Cache a single, deterministic genesis block per network instance to ensure
    // all peers that submit genesis use byte-for-byte identical content.
    cached_genesis: OnceLock<GenesisBlock>,
    // The generated manifest is retained with the cached signed block even
    // when file-backed policies require fresh native pre-execution on each call.
    generated_genesis_manifest: OnceLock<RawGenesisTransaction>,
    // Only immutable, file-free policy inputs may reuse pre-execution validation.
    // File-backed policies retain the ordinary fresh-validation path.
    validated_genesis: Option<OnceLock<ValidatedNetworkGenesis>>,
    config_layers: Vec<Table>,
    topology_entries: Vec<GenesisTopologyEntry>,
    auto_populate_trusted_peer_pops: bool,
    max_validator_capacity: usize,
    _permit: NetworkPermit,
}
/// A block admitted by exact native staging against this network's signed policy.
/// Keeping the block and its returned hashes together prevents a cache marker from
/// accidentally authenticating a different raw/custom block.
#[derive(Clone)]
struct ValidatedNetworkGenesis {
    block: GenesisBlock,
    staged_hashes: config::StagedGenesisPolicyHashes,
    raw_manifest: Option<RawGenesisTransaction>,
}
/// Exact generated manifest and signed block offered to native per-seat genesis provisioning.
///
/// The manifest is retained at the original builder call and verified against
/// this signed block before its serialized bytes are exposed to a subprocess.
#[derive(Clone)]
pub struct NativeGenesisProvisioningBundle {
    /// Canonical JSON bytes of the retained raw genesis manifest.
    pub manifest_json: Vec<u8>,
    /// SHA-256 of `manifest_json`, for asserting the staged file is unchanged.
    pub manifest_sha256: [u8; 32],
    /// Canonical signed-block wire bytes.
    pub signed_wire: Vec<u8>,
    /// Genesis signer public key authenticated by the signed block.
    pub public_key: PublicKey,
    /// Exact block hash used to derive the network ID.
    pub block_hash: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
    /// Exact account-address discriminant in the retained signed manifest.
    pub chain_discriminant: u16,
}
impl ValidatedNetworkGenesis {
    fn new(
        block: GenesisBlock,
        staged_hashes: config::StagedGenesisPolicyHashes,
        raw_manifest: Option<RawGenesisTransaction>,
        profile: &ConsensusBootstrapProfile,
        topology: &[PeerId],
    ) -> Self {
        let validated = Self {
            block,
            staged_hashes,
            raw_manifest,
        };
        validated.assert_matches(profile, topology);
        validated
    }

    fn assert_matches(&self, profile: &ConsensusBootstrapProfile, topology: &[PeerId]) {
        assert_genesis_voting_roster_matches_network(&self.block, topology);
        assert!(
            genesis_has_exactly_one_consensus_handshake(
                &self.block,
                &consensus_handshake_parameter(profile),
            ),
            "cached genesis must retain exactly the signed network handshake"
        );
        assert_eq!(
            self.staged_hashes.nexus_amx,
            CryptoHash::prehashed(profile.params.sumeragi_context.nexus_amx_context_hash),
            "signed test-network Nexus/AMX context must match exact genesis pre-execution"
        );
        assert_eq!(
            self.staged_hashes.execution_policy,
            CryptoHash::prehashed(profile.params.sumeragi_context.execution_policy_hash),
            "signed test-network execution policy must match exact genesis pre-execution"
        );
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        if let Some(relays) = &self.observer_slow_reader_relays {
            relays.abort();
        }
        let keep_tempdir = std::env::var_os(KEEP_TEMPDIR_ENV).is_some();
        if self
            .peers
            .iter()
            .chain(&self.committee_validators)
            .chain(&self.observers)
            .any(NetworkPeer::is_running)
        {
            let peers = self
                .peers
                .iter()
                .chain(&self.committee_validators)
                .chain(&self.observers)
                .cloned()
                .collect();
            let dir = self.env.dir.clone();
            let keep = keep_tempdir;
            std::thread::spawn(move || match runtime::Runtime::new() {
                Ok(rt) => rt.block_on(async {
                    shutdown_peers_for_drop(peers).await;
                    if keep {
                        info!(
                            dir = ?dir,
                            env = KEEP_TEMPDIR_ENV,
                            "preserving test network tempdir for debugging"
                        );
                    } else if let Err(err) = fs::remove_dir_all(&dir) {
                        warn!(
                            dir = ?dir,
                            ?err,
                            "failed to clean up test network tempdir"
                        );
                    }
                }),
                Err(err) => warn!(
                    dir = ?dir,
                    ?err,
                    "failed to create runtime for shutdown; peers may remain running"
                ),
            });
            return;
        }
        if keep_tempdir {
            info!(
                dir = ?self.env.dir,
                env = KEEP_TEMPDIR_ENV,
                "preserving test network tempdir for debugging"
            );
        } else if let Err(err) = fs::remove_dir_all(&self.env.dir) {
            warn!(
                dir = ?self.env.dir,
                ?err,
                "failed to clean up test network tempdir"
            );
        }
    }
}
async fn shutdown_peers_for_drop(peers: Vec<NetworkPeer>) {
    for peer in peers {
        let _ = peer.shutdown_if_started().await;
    }
}
#[derive(Debug, Clone)]
struct ConsensusBootstrapProfile {
    params: ConsensusGenesisParams,
    mode_tag: &'static str,
    bls_domain: &'static str,
    chain_id: ChainId,
    wire_protocol_version: u32,
}
impl ConsensusBootstrapProfile {
    fn fingerprint(&self) -> [u8; 32] {
        compute_consensus_parameters_fingerprint(&self.params)
            .expect("test-network consensus profile must be canonical")
    }
}
fn status_reaches_block_height(
    status: &iroha_torii_shared::status::Status,
    target_height: u64,
) -> bool {
    status.blocks >= target_height
}
async fn run_peer_bootstrap_stages<G, C, O, GV, CV, OV, E>(
    global_validators: G,
    committee_validators: C,
    observers: O,
) -> std::result::Result<(), E>
where
    G: Future<Output = std::result::Result<GV, E>>,
    C: Future<Output = std::result::Result<CV, E>>,
    O: Future<Output = std::result::Result<OV, E>>,
{
    tokio::try_join!(global_validators, committee_validators)?;
    observers.await?;
    Ok(())
}
impl Network {
    /// Path to the temporary directory holding configs and logs for this network.
    pub fn env_dir(&self) -> &Path {
        &self.env.dir
    }
    #[cfg(test)]
    fn consensus_bootstrap_profile(&self) -> ConsensusBootstrapProfile {
        self.consensus_profile.clone()
    }
    fn log_startup_diagnostics(&self) {
        let handshake_fingerprint = self.consensus_profile.fingerprint();
        debug!(
            validators = self.peers.len(),
            committee_validators = self.committee_validators.len(),
            observers = self.observers.len(),
            total_peers = self
                .peers
                .len()
                .saturating_add(self.committee_validators.len())
                .saturating_add(self.observers.len()),
            consensus_block_cadence_ms = self.consensus_profile.params.block_cadence_ms.get(),
            "sumeragi configuration snapshot prior to peer bootstrap"
        );
        info!(
            block_cadence = ?self.block_cadence,
            block_sync_gossip_period = ?self.block_sync_gossip_period,
            consensus_block_cadence_ms = self.consensus_profile.params.block_cadence_ms.get(),
            handshake_mode = self.consensus_profile.mode_tag,
            handshake_bls_domain = self.consensus_profile.bls_domain,
            handshake_protocol_version = self.consensus_profile.wire_protocol_version,
            handshake_fingerprint = %format_args!("0x{}", hex_lower(&handshake_fingerprint)),
            "consensus bootstrap configuration"
        );
    }
    /// Access voting validator peers.
    ///
    /// This preserves the pre-observer meaning of `peers()`: callers may use
    /// its length for consensus quorum calculations without counting replicas.
    pub fn peers(&self) -> &Vec<NetworkPeer> {
        &self.peers
    }
    /// Access voting validator peers explicitly.
    pub fn validators(&self) -> &[NetworkPeer] {
        &self.peers
    }
    /// Access configured participant-committee validators excluded from global quorum.
    pub fn committee_validators(&self) -> &[NetworkPeer] {
        &self.committee_validators
    }
    /// Access signed, non-voting observer replicas.
    pub fn observers(&self) -> &[NetworkPeer] {
        &self.observers
    }
    /// Snapshot transparent slow-reader relay activity, when the harness hook is enabled.
    pub fn observer_slow_reader_relay_stats(&self) -> Option<ObserverSlowReaderRelayStats> {
        self.observer_slow_reader_relays
            .as_ref()
            .map(ObserverSlowReaderRelays::stats)
    }
    /// Snapshot transparent slow-reader relay activity for one observer.
    pub fn observer_slow_reader_relay_stats_for(
        &self,
        observer: &PeerId,
    ) -> Option<ObserverSlowReaderRelayStats> {
        self.observer_slow_reader_relays
            .as_ref()?
            .stats_for(observer)
    }
    /// Pause validator-to-observer forwarding on every transparent slow-reader relay.
    ///
    /// Acknowledgement waits for every in-flight delayed write and its byte-counter
    /// update to retire. New connections use the same gate. Dropping the returned
    /// owner resumes forwarding; shutdown can join connections while it is held.
    /// The caller must bound this acquisition with its existing test deadline.
    /// Returns `None` when this network has no relay hook.
    pub async fn pause_observer_slow_reader_relays(&self) -> Option<ObserverSlowReaderRelayPause> {
        Some(self.observer_slow_reader_relays.as_ref()?.pause().await)
    }
    /// Iterate over global validators, committee validators, then observers.
    pub fn all_peers(&self) -> impl Iterator<Item = &NetworkPeer> {
        self.peers
            .iter()
            .chain(&self.committee_validators)
            .chain(&self.observers)
    }
    fn advertised_p2p_address(&self, peer: &NetworkPeer) -> SocketAddr {
        self.observer_advertised_p2p_addresses
            .get(&peer.network_peer_id())
            .cloned()
            .unwrap_or_else(|| peer.p2p_address())
    }
    fn observer_start_layer(&self, peer: &NetworkPeer) -> Table {
        let Some(published_address) = self
            .observer_advertised_p2p_addresses
            .get(&peer.network_peer_id())
        else {
            return observer_role_layer();
        };
        let outbound_delay_ms = i64::try_from(OBSERVER_RELAY_OUTBOUND_DIAL_DELAY.as_millis())
            .expect("bounded observer relay dial delay fits i64 milliseconds");
        observer_role_layer()
            .write(
                ["network", "public_address"],
                published_address.to_literal(),
            )
            // Keep observer-initiated dials from creating a direct session that
            // bypasses the advertised relay during the bounded integration run.
            .write(["network", "connect_startup_delay_ms"], outbound_delay_ms)
    }
    /// Get the next validator in deterministic round-robin order.
    pub fn peer(&self) -> &NetworkPeer {
        let len = self.peers.len();
        assert!(len > 0, "there is at least one peer");
        let index = self.next_peer_index.fetch_add(1, Ordering::Relaxed) % len;
        &self.peers[index]
    }
    /// Access the environment of the network
    pub fn env(&self) -> &Environment {
        &self.env
    }
    /// Start all peers, waiting until they are up and have committed genesis (submitted by one of them).
    ///
    /// # Panics
    /// - If some peer was already started
    /// - If some peer exists early
    pub async fn start_all(&self) -> Result<&Self> {
        if self.peers.is_empty() {
            return Ok(self);
        }
        self.start_with_genesis_submitters([0]).await
    }
    /// Start peers with an explicit list of genesis submitter indices.
    ///
    /// Genesis submitters are started with a slight stagger to avoid overloading the
    /// network while still allowing multiple peers to race the initial submission.
    /// Replica peers (those not listed as genesis submitters) also ingest the same
    /// genesis block locally to guarantee deterministic bootstrap even if block sync
    /// support is unavailable.
    ///
    /// # Errors
    /// - If any submitter index is out of bounds.
    /// - If peer startup takes longer than [`Self::peer_startup_timeout`].
    pub async fn start_with_genesis_submitters<I>(&self, genesis_submitters: I) -> Result<&Self>
    where
        I: IntoIterator<Item = usize>,
    {
        if self.all_peers().all(NetworkPeer::should_run_bind_preflight) {
            let preflight = preflight_bind_addresses(
                self.all_peers()
                    .flat_map(|peer| [peer.p2p_address(), peer.api_address()]),
            );
            if let Err(err) = preflight {
                return Err(err).wrap_err("preflight bind failed for network peers");
            }
        }
        // Ensure we resolve `iroha3d` once before spawning peers; caches for subsequent calls.
        // A top-level caller may trigger a build, so keep resolution off the async runtime threads.
        let program = self
            .peers
            .first()
            .map_or(Program::Irohad, |peer| peer.program);
        if self.all_peers().any(|peer| peer.program != program) {
            return Err(eyre!(
                "all peers in one test network must use the same daemon program"
            ));
        }
        let _ = program.resolve_async().await?;
        #[cfg(unix)]
        if self
            .all_peers()
            .any(NetworkPeer::has_disposable_runtime_provider_broker)
        {
            let _ = Program::IrohadDisposableBroker.resolve_async().await?;
        }
        let mut submitters: Vec<usize> = genesis_submitters.into_iter().collect();
        submitters.sort_unstable();
        submitters.dedup();
        if submitters.is_empty() && !self.peers.is_empty() {
            submitters.push(0);
        }
        if let Some(&idx) = submitters.iter().find(|&&idx| idx >= self.peers.len()) {
            return Err(eyre!(
                "genesis submitter index {idx} out of range for {} peers",
                self.peers.len()
            ));
        }
        // Canonical encoding can be expensive in debug integration builds. Finish
        // it once, off the async worker, before any validator starts its clock.
        let prepared_genesis = PreparedPeerGenesis::prepare(self.genesis()).await?;
        // Bind every published observer endpoint before validators start. The
        // relay retains accepted sockets and retries the private upstream until
        // the validators-first bootstrap reaches the observer stage.
        if let Some(relays) = &self.observer_slow_reader_relays {
            relays.start().await?;
        }
        let genesis_order = Arc::new(submitters.clone());
        let genesis_lookup = Arc::new(
            submitters
                .iter()
                .enumerate()
                .map(|(pos, &idx)| (idx, pos))
                .collect::<HashMap<usize, usize>>(),
        );
        let startup_timeout = self.peer_startup_timeout();
        info!(
            validators = self.peers.len(),
            committee_validators = self.committee_validators.len(),
            observers = self.observers.len(),
            total_peers = self
                .peers
                .len()
                .saturating_add(self.committee_validators.len())
                .saturating_add(self.observers.len()),
            genesis_submitters = ?submitters,
            ?startup_timeout,
            "bootstrapping test network",
        );
        self.log_startup_diagnostics();
        let start_instant = Instant::now();
        let validator_start_futures = self.peers.iter().enumerate().map(|(index, peer)| {
            let genesis_lookup = genesis_lookup.clone();
            let genesis_order = genesis_order.clone();
            let prepared_genesis = prepared_genesis.clone();
            async move {
                let stage = genesis_lookup.get(&index).copied();
                let mnemonic = peer.mnemonic().to_string();
                let role = if stage.is_some() {
                    "genesis"
                } else {
                    "replica"
                };
                info!(index, %mnemonic, role, "starting peer bootstrap");
                if let Some(stage_idx) = stage {
                    info!(
                        index,
                        %mnemonic,
                        role,
                        stage_idx,
                        total_submitters = genesis_order.len(),
                        "preparing genesis submitter",
                    );
                } else {
                    info!(
                        index,
                        %mnemonic,
                        role,
                        "providing replica with local genesis copy for bootstrap"
                    );
                }
                // Start genesis submitters first, then replicas. This reduces startup contention
                // and makes the genesis submission ordering more deterministic across hosts.
                let start_stage = stage.unwrap_or_else(|| genesis_order.len());
                if start_stage > 0 {
                    let delay = Duration::from_millis(200)
                        .checked_mul(start_stage as u32)
                        .unwrap_or(Duration::from_secs(u64::MAX));
                    info!(
                        index,
                        %mnemonic,
                        role,
                        start_stage,
                        total_submitters = genesis_order.len(),
                        ?delay,
                        "staggering peer startup",
                    );
                    if delay > Duration::ZERO {
                        tokio::time::sleep(delay).await;
                    }
                }
                peer.start_checked_prepared(self.config_layers(), Some(&prepared_genesis))
                    .await?;
                info!(
                    index,
                    %mnemonic,
                    role,
                    "peer started with genesis; waiting for block 1"
                );
                Self::wait_for_block_1_with_watchdog(peer, index, &mnemonic, role).await?;
                Ok::<(), color_eyre::Report>(())
            }
        });
        let bootstrap = async {
            // Supplementary committee validators are not genesis submitters or
            // global voters. Start them concurrently with the global validators
            // so their trusted P2P endpoints are available for genesis traffic,
            // They retain the Validator runtime role for signing. Participant
            // eligibility also requires a live on-chain Committee key record.
            let committee_validator_start_futures = self
                .committee_validators
                .iter()
                .enumerate()
                .map(|(committee_index, peer)| {
                    let prepared_genesis = prepared_genesis.clone();
                    async move {
                        let index = self.peers.len().saturating_add(committee_index);
                        let mnemonic = peer.mnemonic().to_string();
                        let delay = Duration::from_millis(200)
                            .checked_mul(
                                u32::try_from(committee_index.saturating_add(1))
                                    .expect("bounded committee-validator index fits u32"),
                            )
                            .unwrap_or(Duration::from_secs(u64::MAX));
                        if delay > Duration::ZERO {
                            tokio::time::sleep(delay).await;
                        }
                        info!(
                            index,
                            %mnemonic,
                            role = "committee_validator",
                            "starting non-global committee validator"
                        );
                        peer.start_checked_prepared(
                            self.config_layers_for_peer(peer),
                            Some(&prepared_genesis),
                        )
                        .await?;
                        Self::wait_for_block_1_with_watchdog(
                            peer,
                            index,
                            &mnemonic,
                            "committee_validator",
                        )
                        .await?;
                        Ok::<(), color_eyre::Report>(())
                    }
                });
            // Observers are started only after both validator cohorts have
            // committed the one canonical genesis. They receive the same signed
            // block but a node-local role override, so their BLS identities
            // authenticate P2P and block sync without enabling proposal or
            // voting paths.
            let observer_start_futures =
                self.observers
                    .iter()
                    .enumerate()
                    .map(|(observer_index, peer)| {
                        let prepared_genesis = prepared_genesis.clone();
                        let observer_role = self.observer_start_layer(peer);
                        async move {
                            let index = self
                                .peers
                                .len()
                                .saturating_add(self.committee_validators.len())
                                .saturating_add(observer_index);
                            let mnemonic = peer.mnemonic().to_string();
                            let delay = Duration::from_millis(200)
                                .checked_mul(
                                    u32::try_from(observer_index.saturating_add(1))
                                        .expect("bounded observer index fits u32"),
                                )
                                .unwrap_or(Duration::from_secs(u64::MAX));
                            if delay > Duration::ZERO {
                                tokio::time::sleep(delay).await;
                            }
                            info!(
                                index,
                                %mnemonic,
                                role = "observer",
                                "starting signed observer replica"
                            );
                            peer.start_checked_prepared(
                                self.config_layers()
                                    .chain(iter::once(Cow::Owned(observer_role))),
                                Some(&prepared_genesis),
                            )
                            .await?;
                            Self::wait_for_block_1_with_watchdog(
                                peer, index, &mnemonic, "observer",
                            )
                            .await?;
                            Ok::<(), color_eyre::Report>(())
                        }
                    });
            run_peer_bootstrap_stages(
                futures::future::try_join_all(validator_start_futures),
                futures::future::try_join_all(committee_validator_start_futures),
                futures::future::try_join_all(observer_start_futures),
            )
            .await
        };
        match timeout(startup_timeout, bootstrap).await {
            Ok(result) => match result {
                Ok(_) => {
                    self.verify_post_genesis_liveness().await?;
                    info!(
                        elapsed = ?start_instant.elapsed(),
                        "all peers started and passed liveness guard"
                    );
                    Ok(self)
                }
                Err(err) => {
                    let snapshot = self.startup_snapshot();
                    warn!(?snapshot, error = %err, "peer startup failed");
                    self.shutdown().await;
                    let formatted = Self::format_startup_snapshot(&snapshot);
                    Err(err).wrap_err_with(|| {
                        format!("peer startup failed; startup snapshot: [{formatted}]")
                    })
                }
            },
            Err(_) => {
                let snapshot = self.startup_snapshot();
                warn!(?snapshot, "peer startup timed out");
                self.shutdown().await;
                Err(eyre!(
                    "expected peers to start within timeout ({startup_timeout:?}); startup snapshot: [{}]",
                    Self::format_startup_snapshot(&snapshot),
                ))
            }
        }
    }
    async fn verify_post_genesis_liveness(&self) -> Result<()> {
        let window = post_genesis_liveness_window_env();
        if window == Duration::ZERO || self.all_peers().next().is_none() {
            return Ok(());
        }
        let futures = self.all_peers().enumerate().map(|(index, peer)| {
            let mnemonic = peer.mnemonic().to_string();
            let stdout = peer.latest_stdout_log_path();
            let stderr = peer.latest_stderr_log_path();
            let events = peer.events();
            async move {
                if let Some(kind) = detect_peer_termination(events, window).await {
                    Err(eyre!(
                        "peer {index} ({mnemonic}) terminated within {window:?} post-genesis window ({kind:?}); stdout={stdout:?} stderr={stderr:?}"
                    ))
                } else {
                    Ok::<(), color_eyre::Report>(())
                }
            }
        });
        futures::future::try_join_all(futures).await?;
        Ok(())
    }
    async fn wait_for_block_1_with_watchdog(
        peer: &NetworkPeer,
        index: usize,
        mnemonic: &str,
        role: &str,
    ) -> Result<()> {
        let mut latest_status: Option<iroha_torii_shared::status::Status> = None;
        let status_timeout = {
            let configured = peer.client_policy().status_timeout;
            if configured == Duration::ZERO {
                GENESIS_BLOCK_LOG_INTERVAL
            } else {
                configured.min(GENESIS_BLOCK_LOG_INTERVAL)
            }
        };
        let mut poll = tokio::time::interval(Duration::from_millis(250));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut watchdog = tokio::time::interval(GENESIS_BLOCK_LOG_INTERVAL);
        watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut elapsed = Duration::ZERO;
        loop {
            if !peer.is_running() {
                let stdout_log = peer.latest_stdout_log_path();
                let stderr_log = peer.latest_stderr_log_path();
                let context = peer
                    .startup_context_summary()
                    .unwrap_or_else(|| "<startup context not initialized>".to_string());
                if let Some(preview) = peer.stderr_preview() {
                    return Err(eyre!(
                        "peer {index} ({mnemonic}) terminated while waiting for block 1; {context}; stdout={stdout_log:?}; stderr={stderr_log:?}; stderr preview:\n{preview}"
                    ));
                }
                return Err(eyre!(
                    "peer {index} ({mnemonic}) terminated while waiting for block 1; {context}; stdout={stdout_log:?}; stderr={stderr_log:?}"
                ));
            }
            tokio::select! {
                _ = poll.tick() => {
                    match tokio::time::timeout(status_timeout, peer.status()).await {
                        Ok(Ok(status)) => {
                            if status_reaches_block_height(&status, 1) {
                                info!(
                                    index,
                                    %mnemonic,
                                    role,
                                    waited = ?elapsed,
                                    status_blocks = status.blocks,
                                    status_blocks_non_empty = status.blocks_non_empty,
                                    "observed block 1 via status polling"
                                );
                                return Ok(());
                            }
                            latest_status = Some(status);
                        }
                        Ok(Err(error)) => {
                            latest_status = None;
                            let stdout_log = peer.latest_stdout_log_path();
                            let stderr_log = peer.latest_stderr_log_path();
                            warn!(
                                index,
                                %mnemonic,
                                role,
                                ?error,
                                ?stdout_log,
                                ?stderr_log,
                                "status query failed while waiting for block 1"
                            );
                        }
                        Err(_) => {
                            latest_status = None;
                            let stdout_log = peer.latest_stdout_log_path();
                            let stderr_log = peer.latest_stderr_log_path();
                            warn!(
                                index,
                                %mnemonic,
                                role,
                                ?status_timeout,
                                ?stdout_log,
                                ?stderr_log,
                                "status query timed out while waiting for block 1"
                            );
                        }
                    }
                }
                _ = watchdog.tick() => {
                    elapsed += GENESIS_BLOCK_LOG_INTERVAL;
                    let sumeragi = match tokio::time::timeout(
                        status_timeout,
                        peer.sumeragi_startup_snapshot(),
                    )
                    .await
                    {
                        Ok(Ok(snapshot)) => format!("ok({snapshot})"),
                        Ok(Err(error)) => format!(
                            "error(\"{}\")",
                            sanitize_preview_for_display(&format!("{error:?}")),
                        ),
                        Err(_) => {
                            let error = format!("query timed out after {status_timeout:?}");
                            NetworkPeer::record_probe_sumeragi_error(
                                &peer.startup_probe,
                                &error,
                            );
                            format!("error(\"{error}\")")
                        }
                    };
                    if let Some(status) = &latest_status {
                        warn!(
                            index,
                            %mnemonic,
                            role,
                            waited = ?elapsed,
                            status_blocks = status.blocks,
                            status_blocks_non_empty = status.blocks_non_empty,
                            status_queue = status.queue_size,
                            status_view_changes = status.view_changes,
                            sumeragi = %sumeragi,
                            "still waiting for block 1 after genesis submission"
                        );
                    } else {
                        warn!(
                            index,
                            %mnemonic,
                            role,
                            waited = ?elapsed,
                            sumeragi = %sumeragi,
                            "still waiting for block 1; no status snapshot available"
                        );
                    }
                }
            }
        }
    }
    /// Signed immutable block cadence of the network.
    pub fn block_cadence(&self) -> Duration {
        self.block_cadence
    }
    /// DA commit-quorum timeout used by certified-body waits.
    pub fn da_commit_quorum_timeout(&self) -> Duration {
        // Sumeragi's first-release view-change budget is derived from the
        // signed cadence. Keep integration waits outside that protocol budget.
        self.block_cadence.saturating_mul(13)
    }
    /// Block gossip period configured for the network overlay.
    pub fn block_sync_gossip_period(&self) -> Duration {
        self.block_sync_gossip_period
    }
    pub fn sync_timeout(&self) -> Duration {
        self.sync_timeout_override.unwrap_or_else(sync_timeout_env)
    }
    pub fn peer_startup_timeout(&self) -> Duration {
        let base = self
            .peer_startup_timeout_override
            .unwrap_or_else(peer_start_timeout_env);
        let peers = self
            .peers
            .len()
            .saturating_add(self.committee_validators.len())
            .saturating_add(self.observers.len()) as u128;
        if peers == 0 {
            return base;
        }
        // Allow at least 60 seconds per peer by default to accommodate slower DA startup
        // under host contention (e.g., multiple full peers bootstrapping simultaneously).
        let dynamic_secs = u128::from(PEER_STARTUP_TIMEOUT_PER_PEER_SECS)
            .saturating_mul(peers)
            .min(u128::from(u64::MAX));
        let dynamic = Duration::from_secs(dynamic_secs as u64);
        base.max(dynamic)
    }
    /// Capture a human-readable snapshot of the current startup state for all peers.
    pub fn startup_snapshot(&self) -> Vec<PeerStartupState> {
        self.all_peers()
            .enumerate()
            .map(|(index, peer)| peer.startup_state(index))
            .collect()
    }
    fn format_startup_snapshot(snapshot: &[PeerStartupState]) -> String {
        snapshot
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
    /// Get a client for the first peer in the network.
    pub fn client(&self) -> Client {
        self.peers
            .first()
            .expect("there is at least one peer")
            .client()
    }
    /// Chain ID of the network
    pub fn chain_id(&self) -> ChainId {
        self.consensus_profile.chain_id.clone()
    }
    /// Exact network identity derived from this network's signed genesis header.
    pub fn network_id(&self) -> NetworkId {
        NetworkId::from_genesis_hash(self.genesis().0.hash())
    }
    /// Torii URLs for all peers in the network.
    pub fn torii_urls(&self) -> Vec<String> {
        self.all_peers().map(NetworkPeer::torii_url).collect()
    }
    /// Base configuration of all peers.
    ///
    /// Includes `trusted_peers` parameter, containing all currently present peers.
    pub fn config_layers(&self) -> impl Iterator<Item = Cow<'_, Table>> {
        self.config_layers_with_additional_peers([])
    }
    /// Base configuration plus the node-local role for one built peer.
    ///
    /// Global and supplementary committee validators receive the ordinary
    /// shared layers. Signed observers receive the additional fail-closed
    /// observer role (and any observer relay address override), making this the
    /// appropriate layer set for restarting an existing peer without changing
    /// its process capability.
    pub fn config_layers_for_peer<'a>(
        &'a self,
        peer: &'a NetworkPeer,
    ) -> impl Iterator<Item = Cow<'a, Table>> {
        let observer_layer = self
            .observers
            .iter()
            .any(|observer| observer.network_peer_id() == peer.network_peer_id())
            .then(|| Cow::Owned(self.observer_start_layer(peer)));
        self.config_layers().chain(observer_layer)
    }
    /// Base configuration including the current peers and any additional peers provided.
    ///
    /// Useful for bootstrapping validator peers that were registered after the network was built by
    /// threading their PoP into `trusted_peers_pop` so they participate in consensus.
    /// Reserve their capacity with [`NetworkBuilder::with_max_validator_capacity`]
    /// before building and starting the incumbent network.
    ///
    /// # Panics
    ///
    /// Panics when the resulting validator PoP roster exceeds the maximum
    /// capacity reserved by the builder.
    pub fn config_layers_with_additional_peers<'a>(
        &'a self,
        additional_peers: impl IntoIterator<Item = &'a NetworkPeer>,
    ) -> impl Iterator<Item = Cow<'a, Table>> {
        let extra: Vec<&NetworkPeer> = additional_peers.into_iter().collect();
        let mut trusted = self.trusted_peers();
        for peer in &extra {
            let _ = trusted.push(Peer::new(peer.p2p_address(), peer.network_peer_id()));
        }
        // Yield `trusted_peers` first so that any caller-provided layers can
        // reliably override it (e.g., relay/proxy topologies). Later layers in
        // `extends` win during config resolution.
        let trusted_peers: Vec<String> = trusted
            .iter()
            .map(|peer| format!("{}@{}", peer.id(), peer.address().to_literal()))
            .collect();
        let mut base_layer = Table::new().write(["trusted_peers"], trusted_peers);
        // Allow local tooling to bypass Torii pre-auth rate limits. Tests poll status
        // endpoints aggressively while waiting for block 1; without this allowlist the
        // pre-auth ban can trigger and break client traffic.
        base_layer = base_layer.write(
            ["torii", "preauth_allow_cidrs"],
            vec!["127.0.0.1/32", "::1/128"],
        );
        if self.auto_populate_trusted_peer_pops {
            let mut trusted_peers_pop: Vec<Value> = Vec::new();
            let mut seen = HashSet::new();
            // Only validators carry a PoP into the consensus roster. Observers
            // remain BLS-authenticated trusted peers but deliberately have no
            // `trusted_peers_pop` entry.
            for peer in self.peers.iter().chain(extra.into_iter()) {
                let (Some(bls_pk), Some(pop_bytes)) = (peer.bls_public_key(), peer.bls_pop())
                else {
                    continue;
                };
                if !seen.insert(bls_pk.clone()) {
                    continue;
                }
                let mut pop_entry = Table::new();
                pop_entry.insert("public_key".into(), Value::String(bls_pk.to_string()));
                pop_entry.insert(
                    "pop_hex".into(),
                    Value::String(format!("0x{}", hex_lower(pop_bytes))),
                );
                trusted_peers_pop.push(Value::Table(pop_entry));
            }
            if !trusted_peers_pop.is_empty() {
                base_layer =
                    base_layer.write(["trusted_peers_pop"], Value::Array(trusted_peers_pop));
                let validator_roster_len = seen.len();
                assert!(
                    validator_roster_len <= self.max_validator_capacity,
                    "additional validator roster length {validator_roster_len} exceeds the pre-reserved maximum validator capacity {}; declare the future roster with NetworkBuilder::with_max_validator_capacity before starting incumbents",
                    self.max_validator_capacity
                );
            }
        }
        Some(Cow::Owned(base_layer))
            .into_iter()
            .chain(self.config_layers.iter().map(Cow::Borrowed))
    }
    /// Network genesis block.
    ///
    /// It uses the basic [`genesis_factory`] with [`Self::genesis_isi`],
    /// post-topology bootstrap instructions, and the network peer topology.
    /// The signed voting roster is rechecked against the guarded validator
    /// topology before any cached or newly generated block is returned.
    pub fn genesis(&self) -> GenesisBlock {
        let peer_topology: Vec<PeerId> = self.peers.iter().map(NetworkPeer::id).collect();
        if let Some(cache) = &self.validated_genesis {
            // `get_or_init` publishes only after every native validation succeeds;
            // a panic leaves the cell empty and concurrent readers share one result.
            let validated = cache.get_or_init(|| self.prepare_validated_genesis(&peer_topology));
            validated.assert_matches(&self.consensus_profile, &peer_topology);
            return validated.block.clone();
        }
        self.prepare_validated_genesis(&peer_topology).block
    }

    /// Return the retained raw manifest with its exact signed genesis body.
    ///
    /// # Errors
    ///
    /// Custom genesis blocks have no generated raw manifest. An encoding or
    /// signed-manifest mismatch also fails before the bundle can be used.
    pub fn native_genesis_provisioning_bundle(&self) -> Result<NativeGenesisProvisioningBundle> {
        let peer_topology: Vec<PeerId> = self.peers.iter().map(NetworkPeer::id).collect();
        let validated = self.validated_genesis.as_ref().map_or_else(
            || self.prepare_validated_genesis(&peer_topology),
            |cache| {
                cache
                    .get_or_init(|| self.prepare_validated_genesis(&peer_topology))
                    .clone()
            },
        );
        let manifest = validated.raw_manifest.as_ref().ok_or_else(|| {
            eyre!("native genesis provisioning requires the retained generated manifest")
        })?;
        let manifest_json = norito::json::to_vec(manifest)
            .map_err(|error| eyre!("serialize retained genesis manifest: {error}"))?;
        let signed_wire = validated
            .block
            .0
            .encode_wire()
            .map_err(|error| eyre!("encode exact signed genesis: {error}"))?;
        let block_hash = validated.block.0.hash();
        let public_key = self.genesis_key_pair.public_key().clone();
        let verified = iroha_genesis::validate_prepared_genesis_bundle(
            &signed_wire,
            manifest,
            &public_key,
            block_hash,
        )
        .map_err(|error| eyre!("retained raw manifest differs from signed genesis: {error}"))?;
        assert_eq!(
            verified.canonical_wire(),
            signed_wire,
            "per-seat provisioning must consume the exact validated signed genesis bytes"
        );
        let manifest_sha256 = sha256(&manifest_json);
        Ok(NativeGenesisProvisioningBundle {
            manifest_json,
            manifest_sha256,
            signed_wire,
            public_key,
            block_hash,
            chain_discriminant: manifest.chain_discriminant(),
        })
    }

    fn prepare_validated_genesis(&self, peer_topology: &[PeerId]) -> ValidatedNetworkGenesis {
        let config_layers: Vec<Table> = self.config_layers().map(Cow::into_owned).collect();
        let actual_config = Some(resolve_final_actual_config(
            self.peers
                .first()
                .expect("revision-4 test network has at least four validators"),
            &config_layers,
        ));
        let genesis_crypto = actual_config
            .as_ref()
            .map(|config| config::manifest_crypto_from_actual(&config.crypto));
        let da_proof_policies = actual_config
            .as_ref()
            .map(|config| iroha_core::da::proof_policy_bundle(&config.nexus.lane_config));
        let pipeline_config = actual_config.as_ref().map(|config| config.pipeline.clone());
        let nexus_config = actual_config.as_ref().map(|config| config.nexus.clone());
        let zk_config = actual_config.as_ref().map(|config| config.zk.clone());
        let confidential_policy_hash = Some(actual_config.as_ref().map_or_else(
            iroha_core::state::default_genesis_confidential_policy_hash,
            |config| iroha_core::state::compute_genesis_confidential_policy_hash(&config.zk),
        ));
        let consensus_handshake_meta = consensus_handshake_parameter(&self.consensus_profile);
        let genesis_account_id = AccountId::new(self.genesis_key_pair.public_key().clone());
        let recompute_staged_hashes = |block: &GenesisBlock| {
            config::staged_genesis_policy_hashes(
                block,
                &genesis_account_id,
                &peer_topology,
                &self.genesis_key_pair,
                pipeline_config.as_ref(),
                nexus_config.as_ref(),
                zk_config.as_ref(),
                actual_config.as_ref(),
            )
            .expect("signed test-network genesis must stage without synthetic results")
        };
        if let Some(cached_genesis) = self.cached_genesis.get() {
            if genesis_has_exactly_one_consensus_handshake(
                cached_genesis,
                &consensus_handshake_meta,
            ) {
                let staged_hashes = recompute_staged_hashes(cached_genesis);
                return ValidatedNetworkGenesis::new(
                    cached_genesis.clone(),
                    staged_hashes,
                    self.generated_genesis_manifest.get().cloned(),
                    &self.consensus_profile,
                    peer_topology,
                );
            }
            if genesis_contains_any_consensus_handshake(cached_genesis) {
                debug!(
                    "custom genesis consensus_handshake_meta is duplicate or mismatches builder profile; normalizing the canonical consensus parameter"
                );
            }
            let mut augmented = normalize_genesis_parameters(
                cached_genesis,
                &self.genesis_isi,
                &self.genesis_post_topology_isi,
                &consensus_handshake_meta,
                &self.genesis_key_pair,
                da_proof_policies.as_ref(),
                confidential_policy_hash,
            );
            ensure_genesis_results_with_runtime_config(
                &mut augmented,
                &genesis_account_id,
                &peer_topology,
                &self.genesis_key_pair,
                pipeline_config.as_ref(),
                nexus_config.as_ref(),
                zk_config.as_ref(),
                actual_config.as_ref(),
            );
            let staged_hashes = recompute_staged_hashes(&augmented);
            let validated = ValidatedNetworkGenesis::new(
                augmented,
                staged_hashes,
                None,
                &self.consensus_profile,
                peer_topology,
            );
            return validated;
        }
        let (genesis, staged_hash, raw_manifest) =
            config::genesis_with_keypair_and_post_topology_with_policies_and_staged_hash(
                self.genesis_isi.clone(),
                self.genesis_post_topology_isi.clone(),
                self.peers.iter().map(NetworkPeer::id).collect(),
                self.topology_entries.clone(),
                self.genesis_key_pair.clone(),
                self.chain_id(),
                genesis_crypto,
                da_proof_policies,
                pipeline_config.clone(),
                nexus_config.clone(),
                zk_config.clone(),
                actual_config.clone(),
                Some(consensus_handshake_meta),
                None,
                confidential_policy_hash,
            );
        let validated = ValidatedNetworkGenesis::new(
            genesis,
            staged_hash,
            Some(raw_manifest.clone()),
            &self.consensus_profile,
            peer_topology,
        );
        let _ = self.generated_genesis_manifest.set(raw_manifest);
        let _ = self.cached_genesis.set(validated.block.clone());
        validated
    }
    /// Genesis block instructions grouped by transaction
    pub fn genesis_isi(&self) -> &Vec<Vec<InstructionBox>> {
        &self.genesis_isi
    }
    /// BLS Proof-of-Possession entries for the current peer topology.
    pub fn topology_entries(&self) -> &[GenesisTopologyEntry] {
        &self.topology_entries
    }
    /// Shutdown running peers
    pub async fn shutdown(&self) -> &Self {
        self.all_peers()
            .map(|peer| peer.shutdown_if_started())
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>()
            .await;
        if let Some(relays) = &self.observer_slow_reader_relays {
            relays.shutdown().await;
        }
        self
    }
    fn trusted_peers(&self) -> UniqueVec<Peer> {
        self.all_peers()
            .map(|peer| Peer::new(self.advertised_p2p_address(peer), peer.network_peer_id()))
            .collect()
    }
    /// Resolves when all _running_ peers have at least N blocks (non-empty in current policy)
    /// # Errors
    /// If this doesn't happen within a timeout.
    pub async fn ensure_blocks(&self, height: u64) -> Result<&Self> {
        match self
            .ensure_blocks_with(BlockHeight::predicate_total(height))
            .await
        {
            Ok(_) => {}
            Err(err) => {
                warn!(%err, %height, "block sync predicate failed; falling back to status polling");
                self.wait_for_blocks_via_status(height).await?;
            }
        }
        info!(%height, "network sync height");
        Ok(self)
    }
    pub async fn ensure_blocks_with<F: Fn(BlockHeight) -> bool>(&self, f: F) -> Result<&Self> {
        let running_peers: Vec<_> = self.all_peers().filter(|peer| peer.is_running()).collect();
        if running_peers.is_empty() {
            return Ok(self);
        }
        // Fast path: if storage already shows the required height for all running peers,
        // skip the async watchers to avoid long waits when status polling lags behind.
        let storage_satisfied = running_peers.iter().all(|peer| {
            detect_block_height_from_storage(&peer.kura_store_dir(), 0)
                .map(&f)
                .unwrap_or(false)
        });
        if storage_satisfied {
            return Ok(self);
        }
        // Storage markers may lag behind or be absent (e.g., layout migration in progress).
        // Probe `/status` once before wiring block watchers to avoid waiting for fresh block events
        // when peers already satisfy the predicate.
        let mut status_results = Vec::with_capacity(running_peers.len());
        for peer in &running_peers {
            match peer.status().await {
                Ok(status) => {
                    status_results.push(Ok(BlockHeight::from(status)));
                }
                Err(err) => {
                    debug!(
                        ?err,
                        mnemonic = peer.mnemonic(),
                        "status fast path unavailable while ensuring blocks"
                    );
                    status_results.push(Err(()));
                }
            }
        }
        if Self::status_results_satisfy_predicate(status_results.into_iter(), &f) {
            return Ok(self);
        }
        let snapshot_on_failure = || self.startup_snapshot();
        timeout(
            self.sync_timeout(),
            once_blocks_sync(running_peers.into_iter(), &f),
        )
        .await
        .map_err(|_| {
            eyre!(
                "Network overall height did not pass given predicate within timeout; env_dir={}, snapshot={}",
                self.env.dir.display(),
                Self::format_startup_snapshot(&snapshot_on_failure())
            )
        })?
        .map_err(|err| {
            eyre!(
                "block sync predicate failed; env_dir={}, err={err}",
                self.env.dir.display()
            )
        })?;
        Ok(self)
    }
    fn status_results_satisfy_predicate<F, I, E>(results: I, predicate: &F) -> bool
    where
        F: Fn(BlockHeight) -> bool,
        I: IntoIterator<Item = std::result::Result<BlockHeight, E>>,
    {
        results
            .into_iter()
            .all(|result| result.is_ok_and(predicate))
    }
    async fn wait_for_blocks_via_status(&self, height: u64) -> Result<()> {
        let deadline = Instant::now() + self.sync_timeout();
        loop {
            let mut satisfied = true;
            for peer in self.all_peers().filter(|peer| peer.is_running()) {
                match peer.status().await {
                    Ok(status) => {
                        if status.blocks_non_empty < height {
                            satisfied = false;
                            break;
                        }
                    }
                    Err(err) => {
                        // Fall back to on-disk observation so scenarios can progress even if Torii
                        // is slow to accept HTTP connections.
                        if let Some(snapshot) =
                            detect_block_height_from_storage(&peer.dir.join("storage"), 0)
                        {
                            if snapshot.non_empty < height {
                                satisfied = false;
                                break;
                            }
                        } else {
                            satisfied = false;
                            if !peer.is_running() {
                                let stdout = peer.latest_stdout_log_path();
                                let stderr = peer.latest_stderr_log_path();
                                return Err(eyre!(
                                    "peer {} not running while waiting for block {height}; env_dir={}, stdout={stdout:?} stderr={stderr:?}, err={err}",
                                    peer.mnemonic(),
                                    self.env.dir.display()
                                ));
                            }
                            warn!(
                                ?err,
                                mnemonic = peer.mnemonic(),
                                "status poll failed while waiting for block {height}"
                            );
                            break;
                        }
                    }
                }
            }
            if satisfied {
                info!(%height, "network sync height via status");
                return Ok(());
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(eyre!(
            "expected to reach height={height}; env_dir={}",
            self.env.dir.display()
        ))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminationKind {
    Terminated,
    Killed,
    EventStreamClosed,
}
async fn detect_peer_termination(
    mut events: broadcast::Receiver<PeerLifecycleEvent>,
    window: Duration,
) -> Option<TerminationKind> {
    if window == Duration::ZERO {
        return None;
    }
    let timer = tokio::time::sleep(window);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            _ = &mut timer => return None,
            event = events.recv() => match event {
                Ok(PeerLifecycleEvent::Terminated { .. }) => return Some(TerminationKind::Terminated),
                Ok(PeerLifecycleEvent::Killed) => return Some(TerminationKind::Killed),
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Some(TerminationKind::EventStreamClosed),
            }
        }
    }
}
/// Determines how [`NetworkBuilder`] configures [`SmartContractParameter::Fuel`] in the genesis.
#[derive(Clone, Copy, Default)]
pub enum IvmFuelConfig {
    /// Do not set anything, i.e. let Iroha use its default value
    #[default]
    Unset,
    /// Set to a specific value
    Value(NonZero<u64>),
    /// Determine automatically based on the IVM samples build profile
    /// (received from [`iroha_test_samples::load_ivm_build_profile`]).
    ///
    /// If the profile is not optimized, the fuel will be increased, otherwise the same as
    /// [`IvmFuelConfig::Unset`].
    Auto,
}
/// Diagnostic snapshot describing the startup state of a peer.
#[derive(Debug, Clone)]
pub struct PeerStartupState {
    /// Index of the peer within the network builder order.
    pub index: usize,
    /// Mnemonic-derived human readable peer label.
    pub mnemonic: String,
    /// Whether the peer process is still running.
    pub is_running: bool,
    /// Latest observed block height (if any).
    pub last_block: Option<BlockHeight>,
    /// Latest log snapshot information (stdout/stderr paths and previews).
    pub logs: PeerLogSnapshot,
    /// Most recent `/status` response snapshot, if the peer responded.
    pub status_snapshot: Option<PeerStatusSnapshot>,
    /// Most recent `/status` error captured while polling for readiness.
    pub status_error: Option<String>,
    /// Unix timestamp in milliseconds when the status snapshot (success or error) was recorded.
    pub status_unix_timestamp_ms: Option<u128>,
    /// Most recent compact `/v1/sumeragi/status` snapshot, if the peer responded.
    pub sumeragi_snapshot: Option<PeerSumeragiSnapshot>,
    /// Most recent `/v1/sumeragi/status` error captured by the startup watchdog.
    pub sumeragi_error: Option<String>,
    /// Unix timestamp in milliseconds when the Sumeragi probe completed.
    pub sumeragi_unix_timestamp_ms: Option<u128>,
    /// Snapshot of the peer's Kura storage layout.
    pub storage: PeerStorageSnapshot,
}
impl PeerStartupState {
    /// Whether the peer reported a status (i.e., the server started).
    pub fn server_started(&self) -> bool {
        self.last_block.is_some()
    }
}
impl fmt::Display for PeerStartupState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let block = self
            .last_block
            .map(|height| format!("total={} non_empty={}", height.total, height.non_empty))
            .unwrap_or_else(|| "none".to_string());
        write!(
            f,
            "peer#{idx}({name}) running={running} server_started={started} last_block={block}",
            idx = self.index,
            name = self.mnemonic,
            running = self.is_running,
            started = self.server_started(),
            block = block,
        )?;
        let formatted_ts = self
            .status_unix_timestamp_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "unknown".to_string());
        if let Some(snapshot) = &self.status_snapshot {
            write!(
                f,
                "; status=ok(blocks={} non_empty={} queue={} view_changes={} peers={} txs={}/{})@{formatted_ts}",
                snapshot.blocks,
                snapshot.blocks_non_empty,
                snapshot.queue_size,
                snapshot.view_changes,
                snapshot.peers,
                snapshot.txs_approved,
                snapshot.txs_rejected,
            )?;
        } else if let Some(error) = &self.status_error {
            write!(
                f,
                "; status=error(\"{}\")@{formatted_ts}",
                sanitize_preview_for_display(error)
            )?;
        } else {
            write!(f, "; status=unavailable")?;
        }
        let formatted_sumeragi_ts = self
            .sumeragi_unix_timestamp_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "unknown".to_string());
        if let Some(snapshot) = &self.sumeragi_snapshot {
            write!(f, "; sumeragi=ok({snapshot})@{formatted_sumeragi_ts}")?;
        } else if let Some(error) = &self.sumeragi_error {
            write!(
                f,
                "; sumeragi=error(\"{}\")@{formatted_sumeragi_ts}",
                sanitize_preview_for_display(error)
            )?;
        } else {
            write!(f, "; sumeragi=unavailable")?;
        }
        let stdout_log = self
            .logs
            .stdout_log
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string());
        let stderr_log = self
            .logs
            .stderr_log
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string());
        write!(
            f,
            "; logs=stdout={stdout_log} stderr={stderr_log} stderr_run={:?}",
            self.logs.stderr_run_id
        )?;
        if let Some(preview) = &self.logs.stdout_preview {
            write!(
                f,
                " stdout_tail=\"{}\" tail_lines={:?} truncated={}",
                sanitize_preview_for_display(preview),
                self.logs.stdout_preview_line_count,
                self.logs.stdout_truncated
            )?;
        }
        if let Some(preview) = &self.logs.stderr_preview {
            write!(
                f,
                " stderr_tail=\"{}\" tail_lines={:?} total_lines={:?} truncated={}",
                sanitize_preview_for_display(preview),
                self.logs.stderr_preview_line_count,
                self.logs.stderr_total_lines,
                self.logs.stderr_truncated
            )?;
        }
        write!(
            f,
            "; storage=exists={} has_block1={} pipeline={:?} blocks={:?}",
            self.storage.store_exists,
            self.storage.has_block_1_artifact,
            self.storage.pipeline_entries,
            self.storage.blocks_entries,
        )
    }
}
/// Compact projection of `/v1/sumeragi/status` used in startup diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSumeragiSnapshot {
    /// Height of the current round.
    pub height: u64,
    /// View of the current round.
    pub view: u64,
    /// Routing stage of the round.
    pub stage: u8,
    /// View of the lock at the current height, if any.
    pub high_qc_view: Option<u64>,
    /// Pacemaker level of the current view.
    pub level: u32,
    /// Committed tip height.
    pub committed_height: u64,
    /// Highest applied height.
    pub applied_height: u64,
    /// Committed, waiting for the next height's configuration.
    pub awaiting: bool,
    /// The node signs at its current height.
    pub signing: bool,
    /// Some key of the node is unanchored (it signs nothing until anchored).
    pub unanchored: bool,
    /// Why the instance halted, if it did.
    pub halted: Option<String>,
}
impl From<&SumeragiStatus> for PeerSumeragiSnapshot {
    fn from(status: &SumeragiStatus) -> Self {
        Self {
            height: status.height,
            view: status.view,
            stage: status.stage,
            high_qc_view: status.high_qc_view,
            level: status.level,
            committed_height: status.committed_height,
            applied_height: status.applied_height,
            awaiting: status.awaiting,
            signing: status.is_signing(),
            unanchored: status.unanchored,
            halted: status.halted.map(|reason| format!("{reason:?}")),
        }
    }
}
impl fmt::Display for PeerSumeragiSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lock = self
            .high_qc_view
            .map_or_else(|| "-".to_string(), |view| view.to_string());
        write!(
            f,
            "h{}/v{}/s{} level={} lock={} committed={} applied={} awaiting={} signing={} unanchored={} halted={}",
            self.height,
            self.view,
            self.stage,
            self.level,
            lock,
            self.committed_height,
            self.applied_height,
            self.awaiting,
            self.signing,
            self.unanchored,
            self.halted.as_deref().unwrap_or("-"),
        )
    }
}
/// Snapshot of a peer's log state.
#[derive(Debug, Clone, Default)]
pub struct PeerLogSnapshot {
    /// Path to the latest stdout log.
    pub stdout_log: Option<PathBuf>,
    /// Bounded preview of the latest stdout log tail.
    pub stdout_preview: Option<String>,
    /// Number of lines in the stdout preview.
    pub stdout_preview_line_count: Option<usize>,
    /// Whether bytes or lines preceding the stdout preview were omitted.
    pub stdout_truncated: bool,
    /// Path to the latest stderr log (if the peer already exited).
    pub stderr_log: Option<PathBuf>,
    /// Preview of the stderr tail captured from the live stream.
    pub stderr_preview: Option<String>,
    /// Number of lines in the captured preview.
    pub stderr_preview_line_count: Option<usize>,
    /// Total number of stderr lines captured so far.
    pub stderr_total_lines: Option<usize>,
    /// Whether the preview was truncated.
    pub stderr_truncated: bool,
    /// Run identifier associated with the stderr preview.
    pub stderr_run_id: Option<usize>,
}
/// Snapshot of the last `/status` response observed while starting the peer.
#[derive(Debug, Clone, Default)]
pub struct PeerStatusSnapshot {
    pub peers: u64,
    pub blocks: u64,
    pub blocks_non_empty: u64,
    pub commit_time_ms: u64,
    pub queue_size: u64,
    pub view_changes: u32,
    pub txs_approved: u64,
    pub txs_rejected: u64,
}
impl From<&Status> for PeerStatusSnapshot {
    fn from(value: &Status) -> Self {
        Self {
            peers: value.peers,
            blocks: value.blocks,
            blocks_non_empty: value.blocks_non_empty,
            commit_time_ms: value.commit_time_ms,
            queue_size: value.queue_size,
            view_changes: value.view_changes,
            txs_approved: value.txs_approved,
            txs_rejected: value.txs_rejected,
        }
    }
}
/// Snapshot of the peer's Kura directory layout.
#[derive(Debug, Clone)]
pub struct PeerStorageSnapshot {
    pub kura_dir: PathBuf,
    pub store_exists: bool,
    pub has_block_1_artifact: bool,
    pub pipeline_entries: Vec<String>,
    pub blocks_entries: Vec<String>,
}
impl PeerStorageSnapshot {
    fn capture(kura_dir: PathBuf, has_block_1_artifact: bool) -> Self {
        let store_exists = kura_dir.exists();
        let pipeline_entries = pipeline_dirs(&kura_dir)
            .into_iter()
            .find(|dir| dir.exists())
            .map(|dir| snapshot_dir_entries(&dir, STORAGE_LISTING_LIMIT))
            .unwrap_or_default();
        let blocks_entries = snapshot_dir_entries(&kura_dir.join("blocks"), STORAGE_LISTING_LIMIT);
        Self {
            kura_dir,
            store_exists,
            has_block_1_artifact,
            pipeline_entries,
            blocks_entries,
        }
    }
}
#[derive(Debug, Default)]
struct LiveStderrState {
    run_id: Option<usize>,
    buffer: String,
}
impl LiveStderrState {
    fn reset(&mut self, run_id: usize) {
        self.run_id = Some(run_id);
        self.buffer.clear();
    }
    fn push_line(&mut self, line: &str) {
        self.buffer.push_str(line);
        self.buffer.push('\n');
    }
}
#[derive(Debug, Clone, Default)]
struct PeerStartupProbe {
    last_status: Option<PeerStatusSnapshot>,
    last_status_error: Option<String>,
    last_status_unix_ms: Option<u128>,
    last_sumeragi: Option<PeerSumeragiSnapshot>,
    last_sumeragi_error: Option<String>,
    last_sumeragi_unix_ms: Option<u128>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusSource {
    Http,
    Storage,
}
#[derive(Debug, Default)]
struct HttpStartGate {
    seen_http: bool,
}
impl HttpStartGate {
    fn http_seen(&self) -> bool {
        self.seen_http
    }
    /// Returns true exactly once, on the first HTTP-derived status observation.
    fn on_status(&mut self, source: StatusSource) -> bool {
        if self.seen_http {
            false
        } else if matches!(source, StatusSource::Http) {
            self.seen_http = true;
            true
        } else {
            false
        }
    }
}
fn snapshot_dir_entries(path: &Path, limit: usize) -> Vec<String> {
    let Ok(read_dir) = fs::read_dir(path) else {
        return Vec::new();
    };
    let mut names: Vec<String> = read_dir
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    if names.len() > limit {
        let omitted = names.len() - limit;
        names.truncate(limit);
        names.push(format!("(+{omitted} more)"));
    }
    names
}
fn snapshot_snippet(value: &str) -> String {
    let mut buf = String::new();
    for (idx, ch) in value.chars().enumerate() {
        if idx >= SNAPSHOT_MESSAGE_SNIPPET_MAX_CHARS {
            buf.push('…');
            break;
        }
        buf.push(ch);
    }
    buf
}
fn sanitize_preview_for_display(value: &str) -> String {
    snapshot_snippet(&value.replace('\n', "\\n"))
}
async fn drain_log_lines<R, F>(
    output: R,
    mut file: File,
    mut fatal_rx: watch::Receiver<bool>,
    is_running: Arc<AtomicBool>,
    mut on_line: F,
    ready_notify: Option<Arc<Notify>>,
    label: &'static str,
) where
    R: AsyncRead + Unpin,
    F: FnMut(&str),
{
    let mut lines = BufReader::new(output).lines();
    loop {
        if *fatal_rx.borrow() || !is_running.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(line)) => {
                    on_line(&line);
                    if let Err(err) = file.write_all(line.as_bytes()).await {
                        error!(?err, log = label, "writing log line failed");
                        break;
                    }
                    if let Err(err) = file.write_all(b"\n").await {
                        error!(?err, log = label, "writing log newline failed");
                        break;
                    }
                    if let Err(err) = file.flush().await {
                        error!(?err, log = label, "flushing log file failed");
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    error!(?err, log = label, "reading log stream failed");
                    break;
                }
            },
            changed = fatal_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                if *fatal_rx.borrow() {
                    break;
                }
            },
        }
    }
    if let Err(err) = file.flush().await {
        error!(?err, log = label, "flushing log file failed");
    }
    if let Some(notify) = ready_notify {
        notify.notify_waiters();
    }
}
/// Bounded recipe for adding signed, non-voting P2P observers to a test network.
///
/// The descriptor contains only a count. Observer identities and all private
/// key material are created later inside [`NetworkPeer`] instances and never
/// enter this public bootstrap value or the shared trusted-peer layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserverP2pBootstrap {
    observer_count: NonZero<usize>,
}
/// Validation error for [`ObserverP2pBootstrap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverP2pBootstrapError {
    /// At least one observer must be requested when the bootstrap is enabled.
    ZeroObservers,
    /// The observer count alone exceeds the production core-profile connection cap.
    ObserverCountExceedsConnectionCapacity {
        /// Requested observer replicas.
        requested: usize,
        /// Maximum observer replicas possible beside one validator.
        maximum: usize,
    },
    /// Validator and observer counts could not be added without overflow.
    ParticipantCountOverflow {
        /// Voting validator count.
        validators: usize,
        /// Requested observer count.
        observers: usize,
    },
    /// A full trusted-peer fanout would exceed the configured connection cap.
    FanoutExceedsConnectionCapacity {
        /// Voting validator count.
        validators: usize,
        /// Requested observer count.
        observers: usize,
        /// Connections required per participant for full localnet fanout.
        required: usize,
        /// Available total-connection capacity per participant.
        capacity: usize,
    },
}
impl fmt::Display for ObserverP2pBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroObservers => write!(f, "observer bootstrap count must be non-zero"),
            Self::ObserverCountExceedsConnectionCapacity { requested, maximum } => write!(
                f,
                "observer bootstrap count {requested} exceeds the core P2P connection capacity {maximum}"
            ),
            Self::ParticipantCountOverflow {
                validators,
                observers,
            } => write!(
                f,
                "validator count {validators} plus observer count {observers} overflows usize"
            ),
            Self::FanoutExceedsConnectionCapacity {
                validators,
                observers,
                required,
                capacity,
            } => write!(
                f,
                "{validators} validators plus {observers} observers require {required} connections per peer, above capacity {capacity}"
            ),
        }
    }
}
impl std::error::Error for ObserverP2pBootstrapError {}
impl ObserverP2pBootstrap {
    /// Construct a bounded observer recipe.
    ///
    /// The upper bound is derived from the production core lane profile's
    /// total-connection capacity. [`NetworkBuilder`] performs the stricter
    /// validator-aware full-fanout check when the recipe is attached and built.
    ///
    /// # Errors
    /// Returns an error for zero or for a count that cannot fit beside even one
    /// validator under the core P2P connection cap.
    pub fn new(observer_count: usize) -> std::result::Result<Self, ObserverP2pBootstrapError> {
        let observer_count =
            NonZero::new(observer_count).ok_or(ObserverP2pBootstrapError::ZeroObservers)?;
        let maximum = Self::connection_capacity();
        if observer_count.get() > maximum {
            return Err(
                ObserverP2pBootstrapError::ObserverCountExceedsConnectionCapacity {
                    requested: observer_count.get(),
                    maximum,
                },
            );
        }
        Ok(Self { observer_count })
    }
    /// Number of observer replicas requested by this recipe.
    pub const fn observer_count(self) -> usize {
        self.observer_count.get()
    }
    /// Production core-profile total-connection capacity used by the harness.
    pub const fn connection_capacity() -> usize {
        iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS
    }
    fn validate_for_validators(
        self,
        validators: usize,
        capacity: usize,
    ) -> std::result::Result<usize, ObserverP2pBootstrapError> {
        let observers = self.observer_count();
        let participants = validators.checked_add(observers).ok_or(
            ObserverP2pBootstrapError::ParticipantCountOverflow {
                validators,
                observers,
            },
        )?;
        let required = participants.checked_sub(1).ok_or(
            ObserverP2pBootstrapError::ParticipantCountOverflow {
                validators,
                observers,
            },
        )?;
        if required > capacity {
            return Err(ObserverP2pBootstrapError::FanoutExceedsConnectionCapacity {
                validators,
                observers,
                required,
                capacity,
            });
        }
        Ok(participants)
    }
}
/// Bounded recipe for configured validator processes excluded from the global genesis roster.
///
/// Unlike [`ObserverP2pBootstrap`], these processes retain the default
/// `NodeRole::Validator` runtime capability for independently frozen
/// participant-lane work. On-chain eligibility also requires a live Committee
/// consensus-key record. They remain absent from [`Network::peers`], the signed
/// global topology, and global quorum calculations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeValidatorP2pBootstrap {
    validator_count: NonZero<usize>,
}
/// Validation error for [`CommitteeValidatorP2pBootstrap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitteeValidatorP2pBootstrapError {
    /// At least one supplementary committee validator must be requested.
    ZeroValidators,
    /// The supplementary validator count alone exceeds the connection cap.
    ValidatorCountExceedsConnectionCapacity {
        /// Requested supplementary validator processes.
        requested: usize,
        /// Maximum processes possible beside one global validator.
        maximum: usize,
    },
    /// Participant counts could not be added without overflow.
    ParticipantCountOverflow {
        /// Signed global validator count.
        global_validators: usize,
        /// Supplementary committee-validator count.
        committee_validators: usize,
        /// Explicit observer count.
        observers: usize,
    },
    /// A full trusted-peer fanout would exceed the connection cap.
    FanoutExceedsConnectionCapacity {
        /// Signed global validator count.
        global_validators: usize,
        /// Supplementary committee-validator count.
        committee_validators: usize,
        /// Explicit observer count.
        observers: usize,
        /// Connections required per participant.
        required: usize,
        /// Available total-connection capacity per participant.
        capacity: usize,
    },
}
impl fmt::Display for CommitteeValidatorP2pBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroValidators => {
                write!(f, "committee-validator bootstrap count must be non-zero")
            }
            Self::ValidatorCountExceedsConnectionCapacity { requested, maximum } => write!(
                f,
                "committee-validator bootstrap count {requested} exceeds the core P2P connection capacity {maximum}"
            ),
            Self::ParticipantCountOverflow {
                global_validators,
                committee_validators,
                observers,
            } => write!(
                f,
                "{global_validators} global validators plus {committee_validators} committee validators and {observers} observers overflow usize"
            ),
            Self::FanoutExceedsConnectionCapacity {
                global_validators,
                committee_validators,
                observers,
                required,
                capacity,
            } => write!(
                f,
                "{global_validators} global validators plus {committee_validators} committee validators and {observers} observers require {required} connections per peer, above capacity {capacity}"
            ),
        }
    }
}
impl std::error::Error for CommitteeValidatorP2pBootstrapError {}
impl CommitteeValidatorP2pBootstrap {
    /// Construct a bounded supplementary committee-validator recipe.
    ///
    /// # Errors
    /// Returns an error for zero or a count that cannot fit beside even one
    /// global validator under the production core P2P connection cap.
    pub fn new(
        validator_count: usize,
    ) -> std::result::Result<Self, CommitteeValidatorP2pBootstrapError> {
        let validator_count = NonZero::new(validator_count)
            .ok_or(CommitteeValidatorP2pBootstrapError::ZeroValidators)?;
        let maximum = Self::connection_capacity();
        if validator_count.get() > maximum {
            return Err(
                CommitteeValidatorP2pBootstrapError::ValidatorCountExceedsConnectionCapacity {
                    requested: validator_count.get(),
                    maximum,
                },
            );
        }
        Ok(Self { validator_count })
    }
    /// Number of supplementary validator processes requested by this recipe.
    pub const fn validator_count(self) -> usize {
        self.validator_count.get()
    }
    /// Production core-profile total-connection capacity used by the harness.
    pub const fn connection_capacity() -> usize {
        ObserverP2pBootstrap::connection_capacity()
    }
    fn validate_for_network(
        self,
        global_validators: usize,
        observers: usize,
        capacity: usize,
    ) -> std::result::Result<usize, CommitteeValidatorP2pBootstrapError> {
        let committee_validators = self.validator_count();
        let participants = global_validators
            .checked_add(committee_validators)
            .and_then(|count| count.checked_add(observers))
            .ok_or(
                CommitteeValidatorP2pBootstrapError::ParticipantCountOverflow {
                    global_validators,
                    committee_validators,
                    observers,
                },
            )?;
        let required = participants.checked_sub(1).ok_or(
            CommitteeValidatorP2pBootstrapError::ParticipantCountOverflow {
                global_validators,
                committee_validators,
                observers,
            },
        )?;
        if required > capacity {
            return Err(
                CommitteeValidatorP2pBootstrapError::FanoutExceedsConnectionCapacity {
                    global_validators,
                    committee_validators,
                    observers,
                    required,
                    capacity,
                },
            );
        }
        Ok(participants)
    }
}
const OBSERVER_SLOW_READER_MAX_CHUNK_BYTES: usize = 64 * 1024;
const OBSERVER_SLOW_READER_MAX_DELAY: Duration = Duration::from_secs(1);
const OBSERVER_RELAY_UPSTREAM_RETRY_DELAY: Duration = Duration::from_millis(25);
const OBSERVER_RELAY_OUTBOUND_DIAL_DELAY: Duration = Duration::from_secs(24 * 60 * 60);
/// Bounded transparent-relay settings for observer slow-reader tests.
///
/// The relay does not decode or alter P2P traffic. It only limits each read
/// from a validator-facing TCP socket and delays forwarding that ciphertext to
/// the real observer listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserverSlowReaderRelayConfig {
    read_chunk_bytes: NonZero<usize>,
    read_delay: Duration,
}
/// Validation error for [`ObserverSlowReaderRelayConfig`] or its builder hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverSlowReaderRelayError {
    /// A relay was requested before any observer bootstrap was attached.
    MissingObserverBootstrap,
    /// A read chunk must contain at least one byte.
    ZeroReadChunkBytes,
    /// A read chunk exceeded the bounded relay allocation limit.
    ReadChunkBytesExceedsLimit {
        /// Requested bytes per read.
        requested: usize,
        /// Maximum bytes per read.
        maximum: usize,
    },
    /// Each forwarded read must have a non-zero delay.
    ZeroReadDelay,
    /// The per-read delay exceeded the bounded test-harness limit.
    ReadDelayExceedsLimit {
        /// Requested delay.
        requested: Duration,
        /// Maximum delay.
        maximum: Duration,
    },
}
impl fmt::Display for ObserverSlowReaderRelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingObserverBootstrap => {
                write!(
                    f,
                    "observer slow-reader relays require an observer bootstrap"
                )
            }
            Self::ZeroReadChunkBytes => write!(f, "observer relay read chunk must be non-zero"),
            Self::ReadChunkBytesExceedsLimit { requested, maximum } => write!(
                f,
                "observer relay read chunk {requested} exceeds the {maximum}-byte limit"
            ),
            Self::ZeroReadDelay => write!(f, "observer relay read delay must be non-zero"),
            Self::ReadDelayExceedsLimit { requested, maximum } => write!(
                f,
                "observer relay read delay {requested:?} exceeds the {maximum:?} limit"
            ),
        }
    }
}
impl std::error::Error for ObserverSlowReaderRelayError {}
impl ObserverSlowReaderRelayConfig {
    /// Construct bounded transparent-relay settings.
    ///
    /// # Errors
    /// Returns an error for a zero or over-limit read chunk, or a zero or
    /// over-limit delay.
    pub fn new(
        read_chunk_bytes: usize,
        read_delay: Duration,
    ) -> std::result::Result<Self, ObserverSlowReaderRelayError> {
        let read_chunk_bytes = NonZero::new(read_chunk_bytes)
            .ok_or(ObserverSlowReaderRelayError::ZeroReadChunkBytes)?;
        if read_chunk_bytes.get() > OBSERVER_SLOW_READER_MAX_CHUNK_BYTES {
            return Err(ObserverSlowReaderRelayError::ReadChunkBytesExceedsLimit {
                requested: read_chunk_bytes.get(),
                maximum: OBSERVER_SLOW_READER_MAX_CHUNK_BYTES,
            });
        }
        if read_delay == Duration::ZERO {
            return Err(ObserverSlowReaderRelayError::ZeroReadDelay);
        }
        if read_delay > OBSERVER_SLOW_READER_MAX_DELAY {
            return Err(ObserverSlowReaderRelayError::ReadDelayExceedsLimit {
                requested: read_delay,
                maximum: OBSERVER_SLOW_READER_MAX_DELAY,
            });
        }
        Ok(Self {
            read_chunk_bytes,
            read_delay,
        })
    }
    /// Maximum read-chunk allocation accepted by the harness.
    pub const fn maximum_read_chunk_bytes() -> usize {
        OBSERVER_SLOW_READER_MAX_CHUNK_BYTES
    }
    /// Maximum per-read delay accepted by the harness.
    pub const fn maximum_read_delay() -> Duration {
        OBSERVER_SLOW_READER_MAX_DELAY
    }
    /// Bytes read from the validator-facing socket per delayed operation.
    pub const fn read_chunk_bytes(self) -> usize {
        self.read_chunk_bytes.get()
    }
    /// Delay applied to each non-empty validator-to-observer read.
    pub const fn read_delay(self) -> Duration {
        self.read_delay
    }
}
/// Exclusive forwarding hold for every observer relay in one test network.
///
/// This owns the acknowledged pause boundary. Dropping it resumes ciphertext
/// forwarding. It changes no consensus message, node configuration, or counter.
#[derive(Debug)]
#[must_use = "dropping the pause owner resumes observer forwarding"]
pub struct ObserverSlowReaderRelayPause {
    _forwarding: OwnedRwLockWriteGuard<()>,
}
/// Snapshot of transparent observer-relay activity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObserverSlowReaderRelayStats {
    /// Validator-facing TCP connections accepted by the relays.
    pub accepted_connections: u64,
    /// Accepted connections paired with a real observer listener.
    pub upstream_connections: u64,
    /// Failed upstream connection attempts while waiting for observers to start.
    pub upstream_connect_retries: u64,
    /// Non-empty validator-to-observer reads subjected to the configured delay.
    pub delayed_reads: u64,
    /// Unmodified validator-to-observer ciphertext bytes forwarded upstream.
    pub forwarded_to_observers_bytes: u64,
}
#[derive(Debug, Default)]
struct ObserverSlowReaderRelayCounters {
    accepted_connections: AtomicU64,
    upstream_connections: AtomicU64,
    upstream_connect_retries: AtomicU64,
    delayed_reads: AtomicU64,
    forwarded_to_observers_bytes: AtomicU64,
}
impl ObserverSlowReaderRelayCounters {
    fn snapshot(&self) -> ObserverSlowReaderRelayStats {
        ObserverSlowReaderRelayStats {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            upstream_connections: self.upstream_connections.load(Ordering::Relaxed),
            upstream_connect_retries: self.upstream_connect_retries.load(Ordering::Relaxed),
            delayed_reads: self.delayed_reads.load(Ordering::Relaxed),
            forwarded_to_observers_bytes: self.forwarded_to_observers_bytes.load(Ordering::Relaxed),
        }
    }
}
#[derive(Debug)]
struct ObserverSlowReaderRelayRoute {
    peer_id: PeerId,
    published_address: SocketAddr,
    upstream_address: SocketAddr,
    counters: Arc<ObserverSlowReaderRelayCounters>,
    _published_port: AllocatedPort,
}
#[derive(Debug, Default)]
struct ObserverSlowReaderRelayRuntime {
    shutdown: Option<watch::Sender<bool>>,
    listeners: Vec<JoinHandle<()>>,
}
#[derive(Debug)]
struct ObserverSlowReaderRelays {
    config: ObserverSlowReaderRelayConfig,
    routes: Vec<ObserverSlowReaderRelayRoute>,
    published_addresses: HashMap<PeerId, SocketAddr>,
    running: AtomicBool,
    forwarding: Arc<RwLock<()>>,
    runtime: StdMutex<ObserverSlowReaderRelayRuntime>,
}
impl ObserverSlowReaderRelays {
    fn new(observers: &[NetworkPeer], config: ObserverSlowReaderRelayConfig) -> Self {
        let routes = observers
            .iter()
            .map(|observer| {
                let published_port = AllocatedPort::new();
                let published_address = socket_addr!(127.0.0.1:*published_port);
                ObserverSlowReaderRelayRoute {
                    peer_id: observer.network_peer_id(),
                    published_address,
                    upstream_address: observer.p2p_address(),
                    counters: Arc::new(ObserverSlowReaderRelayCounters::default()),
                    _published_port: published_port,
                }
            })
            .collect::<Vec<_>>();
        let published_addresses = routes
            .iter()
            .map(|route| (route.peer_id.clone(), route.published_address.clone()))
            .collect();
        Self {
            config,
            routes,
            published_addresses,
            running: AtomicBool::new(false),
            forwarding: Arc::new(RwLock::new(())),
            runtime: StdMutex::new(ObserverSlowReaderRelayRuntime::default()),
        }
    }
    fn published_addresses(&self) -> HashMap<PeerId, SocketAddr> {
        self.published_addresses.clone()
    }
    fn stats(&self) -> ObserverSlowReaderRelayStats {
        self.routes.iter().fold(
            ObserverSlowReaderRelayStats::default(),
            |mut aggregate, route| {
                let route = route.counters.snapshot();
                aggregate.accepted_connections = aggregate
                    .accepted_connections
                    .saturating_add(route.accepted_connections);
                aggregate.upstream_connections = aggregate
                    .upstream_connections
                    .saturating_add(route.upstream_connections);
                aggregate.upstream_connect_retries = aggregate
                    .upstream_connect_retries
                    .saturating_add(route.upstream_connect_retries);
                aggregate.delayed_reads =
                    aggregate.delayed_reads.saturating_add(route.delayed_reads);
                aggregate.forwarded_to_observers_bytes = aggregate
                    .forwarded_to_observers_bytes
                    .saturating_add(route.forwarded_to_observers_bytes);
                aggregate
            },
        )
    }
    fn stats_for(&self, peer_id: &PeerId) -> Option<ObserverSlowReaderRelayStats> {
        self.routes
            .iter()
            .find(|route| &route.peer_id == peer_id)
            .map(|route| route.counters.snapshot())
    }
    async fn pause(&self) -> ObserverSlowReaderRelayPause {
        ObserverSlowReaderRelayPause {
            _forwarding: Arc::clone(&self.forwarding).write_owned().await,
        }
    }
    async fn start(&self) -> Result<()> {
        let mut runtime = self
            .runtime
            .lock()
            .expect("observer relay runtime should not be poisoned");
        if self.running.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut bound = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            match TcpListener::bind(route.published_address.to_string()).and_then(|listener| {
                listener.set_nonblocking(true)?;
                TokioTcpListener::from_std(listener)
            }) {
                Ok(listener) => bound.push((listener, route)),
                Err(error) => {
                    return Err(error).wrap_err_with(|| {
                        format!(
                            "failed to bind observer slow-reader relay {} for {}",
                            route.published_address, route.peer_id
                        )
                    });
                }
            }
        }
        let (shutdown, shutdown_rx) = watch::channel(false);
        let listeners = bound
            .into_iter()
            .map(|(listener, route)| {
                let counters = Arc::clone(&route.counters);
                let config = self.config;
                let shutdown_rx = shutdown_rx.clone();
                let forwarding = Arc::clone(&self.forwarding);
                let peer_id = route.peer_id.clone();
                let published_address = route.published_address.clone();
                let upstream_address = route.upstream_address.clone();
                tokio::spawn(async move {
                    run_observer_slow_reader_listener(
                        listener,
                        peer_id,
                        published_address,
                        upstream_address,
                        config,
                        counters,
                        shutdown_rx,
                        forwarding,
                    )
                    .await;
                })
            })
            .collect();
        runtime.shutdown = Some(shutdown);
        runtime.listeners = listeners;
        self.running.store(true, Ordering::Release);
        Ok(())
    }
    async fn shutdown(&self) {
        let listeners = self.signal_shutdown_and_take_listeners();
        for listener in listeners {
            let _ = listener.await;
        }
    }
    fn abort(&self) {
        for listener in self.signal_shutdown_and_take_listeners() {
            listener.abort();
        }
    }
    fn signal_shutdown_and_take_listeners(&self) -> Vec<JoinHandle<()>> {
        let mut runtime = self
            .runtime
            .lock()
            .expect("observer relay runtime should not be poisoned");
        self.running.store(false, Ordering::Release);
        if let Some(shutdown) = runtime.shutdown.take() {
            let _ = shutdown.send(true);
        }
        std::mem::take(&mut runtime.listeners)
    }
}
impl Drop for ObserverSlowReaderRelays {
    fn drop(&mut self) {
        self.abort();
    }
}
async fn run_observer_slow_reader_listener(
    listener: TokioTcpListener,
    peer_id: PeerId,
    published_address: SocketAddr,
    upstream_address: SocketAddr,
    config: ObserverSlowReaderRelayConfig,
    counters: Arc<ObserverSlowReaderRelayCounters>,
    mut shutdown: watch::Receiver<bool>,
    forwarding: Arc<RwLock<()>>,
) {
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    debug!(%error, %peer_id, "observer relay connection task failed");
                }
                continue;
            }
        };
        let (client, _) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                warn!(%error, %peer_id, %published_address, "observer relay accept failed");
                break;
            }
        };
        counters
            .accepted_connections
            .fetch_add(1, Ordering::Relaxed);
        let connection_counters = Arc::clone(&counters);
        let connection_shutdown = shutdown.clone();
        let connection_forwarding = Arc::clone(&forwarding);
        let connection_peer_id = peer_id.clone();
        let connection_upstream = upstream_address.clone();
        connections.spawn(async move {
            run_observer_slow_reader_connection(
                client,
                connection_peer_id,
                connection_upstream,
                config,
                connection_counters,
                connection_shutdown,
                connection_forwarding,
            )
            .await;
        });
    }
    connections.shutdown().await;
}
async fn run_observer_slow_reader_connection(
    client: TcpStream,
    peer_id: PeerId,
    upstream_address: SocketAddr,
    config: ObserverSlowReaderRelayConfig,
    counters: Arc<ObserverSlowReaderRelayCounters>,
    mut shutdown: watch::Receiver<bool>,
    forwarding: Arc<RwLock<()>>,
) {
    let upstream = loop {
        let connect = TcpStream::connect(upstream_address.to_string());
        match tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            connected = connect => connected,
        } {
            Ok(upstream) => break upstream,
            Err(_error) => {
                counters
                    .upstream_connect_retries
                    .fetch_add(1, Ordering::Relaxed);
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                    () = tokio::time::sleep(OBSERVER_RELAY_UPSTREAM_RETRY_DELAY) => {}
                }
            }
        }
    };
    counters
        .upstream_connections
        .fetch_add(1, Ordering::Relaxed);
    let (client_read, mut client_write) = client.into_split();
    let (mut upstream_read, upstream_write) = upstream.into_split();
    let delayed = slow_copy_observer_ciphertext(
        client_read,
        upstream_write,
        config,
        Arc::clone(&counters),
        shutdown.clone(),
        forwarding,
    );
    let returned = tokio::io::copy(&mut upstream_read, &mut client_write);
    tokio::pin!(delayed);
    tokio::pin!(returned);
    tokio::select! {
        changed = shutdown.changed() => {
            let _ = changed;
        }
        result = &mut delayed => {
            if let Err(error) = result {
                debug!(%error, %peer_id, "observer relay delayed direction closed");
            }
        }
        result = &mut returned => {
            if let Err(error) = result {
                debug!(%error, %peer_id, "observer relay return direction closed");
            }
        }
    }
}
async fn slow_copy_observer_ciphertext<R, W>(
    mut reader: R,
    mut writer: W,
    config: ObserverSlowReaderRelayConfig,
    counters: Arc<ObserverSlowReaderRelayCounters>,
    mut shutdown: watch::Receiver<bool>,
    forwarding: Arc<RwLock<()>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; config.read_chunk_bytes()];
    loop {
        let read = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            read = reader.read(&mut buffer) => read?,
        };
        if read == 0 {
            return Ok(());
        }
        counters.delayed_reads.fetch_add(1, Ordering::Relaxed);
        // A writer queues ahead of subsequent readers, so a requested pause
        // drains earlier complete writes without admitting another forwarding
        // operation. The read owner also covers the completed-byte increment.
        let forwarding_owner = tokio::select! {
            changed = shutdown.changed() => {
                let _ = changed;
                return Ok(());
            }
            owner = Arc::clone(&forwarding).read_owned() => owner,
        };
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            () = tokio::time::sleep(config.read_delay()) => {}
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            result = writer.write_all(&buffer[..read]) => result?,
        }
        counters
            .forwarded_to_observers_bytes
            .fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
        drop(forwarding_owner);
    }
}
#[derive(Clone)]
enum ParliamentTestSignerSelection {
    AllValid,
    PerPeer(Vec<ParliamentBeaconSignerMode>),
}

impl ParliamentTestSignerSelection {
    fn resolve(&self, validator_count: usize) -> Vec<ParliamentBeaconSignerMode> {
        match self {
            Self::AllValid => vec![ParliamentBeaconSignerMode::Valid; validator_count],
            Self::PerPeer(modes) => {
                assert_eq!(
                    modes.len(),
                    validator_count,
                    "Parliament beacon signer modes must name every validator exactly once",
                );
                modes.clone()
            }
        }
    }
}

/// Builder of [`Network`].
///
/// Cloning copies only the deterministic network recipe. Every call to
/// [`Self::build`] allocates a distinct environment, peer directories, and
/// ports, which lets startup retries remain isolated from prior durable state.
#[derive(Clone)]
pub struct NetworkBuilder {
    n_peers: usize,
    max_validator_capacity: Option<usize>,
    committee_validator_p2p_bootstrap: Option<CommitteeValidatorP2pBootstrap>,
    observer_p2p_bootstrap: Option<ObserverP2pBootstrap>,
    observer_slow_reader_relays: Option<ObserverSlowReaderRelayConfig>,
    config_layers: Vec<Table>,
    block_cadence: Option<Duration>,
    sync_timeout: Option<Duration>,
    peer_startup_timeout: Option<Duration>,
    ivm_fuel: IvmFuelConfig,
    genesis_isi: Vec<Vec<InstructionBox>>,
    genesis_post_topology_isi: Vec<Vec<InstructionBox>>,
    custom_genesis: Option<GenesisBuilderFn>,
    seed: Option<String>,
    genesis_key_pair: KeyPair,
    block_sync_gossip_period: Duration,
    consensus_mode: ConsensusMode,
    auto_populate_trusted_peer_pops: bool,
    genesis_committee_keys_for_global_peers: bool,
    npos_genesis_bootstrap_stake: Option<Quantity>,
    private_settlement_route_control: bool,
    parliament_test_signers: Option<ParliamentTestSignerSelection>,
    topology_genesis_isi: Vec<Arc<TopologyGenesisIsi>>,
}
/// Post-topology genesis instructions derived from the signed voting topology (peer ids and
/// proofs of possession, in topology order).
type TopologyGenesisIsi = dyn Fn(&[GenesisTopologyEntry]) -> Vec<InstructionBox> + Send + Sync;
fn merge_tables(dst: &mut Table, src: &Table) {
    for (key, value) in src {
        match value {
            Value::Table(src_table) => match dst.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    if let Value::Table(dst_table) = entry.get_mut() {
                        merge_tables(dst_table, src_table);
                    } else {
                        entry.insert(Value::Table(src_table.clone()));
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(Value::Table(src_table.clone()));
                }
            },
            _ => {
                dst.insert(key.clone(), value.clone());
            }
        }
    }
}
fn effective_network_reply_source_capacity(
    network: &iroha_config::parameters::actual::Network,
) -> usize {
    network
        .max_total_connections
        .or(network.lane_profile.derived_limits().max_total_connections)
        .map_or(
            network.lane_profile.defaults().max_total_connections,
            NonZero::get,
        )
}
fn validate_planned_validator_capacity(
    config: &iroha_config::parameters::actual::Root,
    max_validator_capacity: usize,
) -> Result<()> {
    let bootstrap_validator_count = config.common.trusted_peers.value().validator_roster_len();
    if max_validator_capacity < bootstrap_validator_count {
        return Err(eyre!(
            "reserved maximum validator capacity {max_validator_capacity} is below the final bootstrap roster of {bootstrap_validator_count} validators"
        ));
    }
    if max_validator_capacity > MAX_VALIDATORS_PER_HEIGHT {
        return Err(eyre!(
            "reserved maximum validator capacity {max_validator_capacity} exceeds the protocol ceiling {MAX_VALIDATORS_PER_HEIGHT}"
        ));
    }
    let reply_source_capacity = effective_network_reply_source_capacity(&config.network);
    let additional_validators = max_validator_capacity
        .checked_sub(bootstrap_validator_count)
        .ok_or_else(|| {
            eyre!(
                "planned test-network validator growth underflowed from {bootstrap_validator_count} bootstrap validators to a {max_validator_capacity}-validator reservation"
            )
        })?;
    let current_remote_trusted = config.common.trusted_peers.value().others.len();
    let required_full_fanout = current_remote_trusted
        .checked_add(additional_validators)
        .ok_or_else(|| {
            eyre!(
                "planned test-network full-fanout geometry overflowed from {current_remote_trusted} current remote trusted peers and {additional_validators} additional validators"
            )
        })?;
    if reply_source_capacity < required_full_fanout {
        return Err(eyre!(
            "final caller layers leave the effective network connection capacity {reply_source_capacity} below the planned full-fanout minimum {required_full_fanout}: {current_remote_trusted} current remote trusted peers plus {additional_validators} additional validators for a {max_validator_capacity}-validator reservation"
        ));
    }
    Ok(())
}
#[cfg(test)]
fn trusted_peers_layer_for_parse(
    peers: &[NetworkPeer],
    auto_populate_trusted_peer_pops: bool,
) -> Table {
    trusted_peers_layer_for_parse_with_observers(peers, &[], auto_populate_trusted_peer_pops)
}
#[cfg(test)]
fn trusted_peers_layer_for_parse_with_observers(
    validators: &[NetworkPeer],
    observers: &[NetworkPeer],
    auto_populate_trusted_peer_pops: bool,
) -> Table {
    trusted_peers_layer_for_parse_with_observer_addresses(
        validators,
        &[],
        observers,
        &HashMap::new(),
        auto_populate_trusted_peer_pops,
    )
}
fn trusted_peers_layer_for_parse_with_observer_addresses(
    validators: &[NetworkPeer],
    committee_validators: &[NetworkPeer],
    observers: &[NetworkPeer],
    observer_advertised_p2p_addresses: &HashMap<PeerId, SocketAddr>,
    auto_populate_trusted_peer_pops: bool,
) -> Table {
    let trusted_peers: Vec<String> = validators
        .iter()
        .chain(committee_validators)
        .chain(observers)
        .map(|peer| {
            let address = observer_advertised_p2p_addresses
                .get(&peer.network_peer_id())
                .cloned()
                .unwrap_or_else(|| peer.p2p_address());
            format!("{}@{}", peer.network_peer_id(), address.to_literal())
        })
        .collect();
    let mut base_layer = Table::new().write(["trusted_peers"], trusted_peers);
    if auto_populate_trusted_peer_pops {
        let mut trusted_peers_pop: Vec<Value> = Vec::new();
        let mut seen = HashSet::new();
        for peer in validators {
            let (Some(bls_pk), Some(pop_bytes)) = (peer.bls_public_key(), peer.bls_pop()) else {
                continue;
            };
            if !seen.insert(bls_pk.clone()) {
                continue;
            }
            let mut pop_entry = Table::new();
            pop_entry.insert("public_key".into(), Value::String(bls_pk.to_string()));
            pop_entry.insert(
                "pop_hex".into(),
                Value::String(format!("0x{}", hex_lower(pop_bytes))),
            );
            trusted_peers_pop.push(Value::Table(pop_entry));
        }
        if !trusted_peers_pop.is_empty() {
            base_layer = base_layer.write(["trusted_peers_pop"], Value::Array(trusted_peers_pop));
        }
    }
    base_layer
}
fn observer_role_layer() -> Table {
    Table::new().write(["sumeragi", "role"], "observer")
}
// Deterministic BLS keypair/PoP so consensus validation doesn't reject profile detection defaults.
const SORA_PROFILE_BLS_PUBLIC_KEY: &str = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2";
const SORA_PROFILE_BLS_PRIVATE_KEY: &str =
    "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F";
static SORA_PROFILE_BLS_KEYPAIR: OnceLock<KeyPair> = OnceLock::new();
static SORA_PROFILE_BLS_POP_HEX: OnceLock<String> = OnceLock::new();
const SORA_PROFILE_STREAM_PUBLIC_KEY: &str =
    "ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B";
const SORA_PROFILE_STREAM_PRIVATE_KEY: &str =
    "802620282ED9F3CF92811C3818DBC4AE594ED59DC1A2F78E4241E31924E101D6B1FB83";
static SORA_PROFILE_STREAM_KEYPAIR: OnceLock<KeyPair> = OnceLock::new();
static SORA_PROFILE_SORANET_TRANSPORT_KEYPAIR: OnceLock<KeyPair> = OnceLock::new();
// Schema-completion sentinel used only while projecting genesis-dependent
// runtime configuration before the signed genesis block exists. It is never
// emitted into a peer run config and must not be treated as a trust anchor.
const NON_RUNTIME_GENESIS_EXPECTED_HASH_BODY_FOR_CONFIG_PROJECTION: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
fn genesis_expected_hash_config_literal(hash_body: &str) -> String {
    norito::literal::format("hash", &hash_body.to_ascii_uppercase())
}
fn ensure_non_runtime_genesis_expected_hash_for_config_projection(table: &mut Table) {
    let genesis = table
        .entry("genesis".to_owned())
        .or_insert_with(|| Value::Table(Table::new()));
    let Some(genesis) = genesis.as_table_mut() else {
        // Preserve an invalid non-table value so normal config parsing reports it.
        return;
    };
    genesis
        .entry("expected_hash".to_owned())
        .or_insert_with(|| {
            Value::String(genesis_expected_hash_config_literal(
                NON_RUNTIME_GENESIS_EXPECTED_HASH_BODY_FOR_CONFIG_PROJECTION,
            ))
        });
}
fn sora_profile_bls_pop_hex() -> &'static str {
    SORA_PROFILE_BLS_POP_HEX.get_or_init(|| {
        let bls_keypair = SORA_PROFILE_BLS_KEYPAIR.get_or_init(|| {
            let public_key: PublicKey = SORA_PROFILE_BLS_PUBLIC_KEY
                .parse()
                .expect("sora profile BLS public key should parse");
            let private_key: PrivateKey = SORA_PROFILE_BLS_PRIVATE_KEY
                .parse()
                .expect("sora profile BLS private key should parse");
            KeyPair::new(public_key, private_key).expect("sora profile BLS keypair should match")
        });
        let pop = iroha_crypto::bls_normal_pop_prove(bls_keypair.private_key())
            .expect("sora profile BLS PoP should generate");
        format!("0x{}", hex_lower(&pop))
    })
}
fn ensure_sora_profile_trusted_peer_pop(table: &mut Table) {
    let mut pop_entry = Table::new();
    pop_entry.insert(
        "public_key".into(),
        Value::String(SORA_PROFILE_BLS_PUBLIC_KEY.to_string()),
    );
    pop_entry.insert(
        "pop_hex".into(),
        Value::String(sora_profile_bls_pop_hex().to_string()),
    );
    let entry = Value::Table(pop_entry);
    match table.get_mut("trusted_peers_pop") {
        Some(Value::Array(entries)) if entries.is_empty() => entries.push(entry),
        Some(Value::Array(_)) => {}
        None => {
            table.insert("trusted_peers_pop".into(), Value::Array(vec![entry]));
        }
        Some(_) => {}
    }
}
fn sora_profile_detection_defaults() -> Table {
    let bls_keypair = SORA_PROFILE_BLS_KEYPAIR.get_or_init(|| {
        let public_key: PublicKey = SORA_PROFILE_BLS_PUBLIC_KEY
            .parse()
            .expect("sora profile BLS public key should parse");
        let private_key: PrivateKey = SORA_PROFILE_BLS_PRIVATE_KEY
            .parse()
            .expect("sora profile BLS private key should parse");
        KeyPair::new(public_key, private_key).expect("sora profile BLS keypair should match")
    });
    let streaming_keypair = SORA_PROFILE_STREAM_KEYPAIR.get_or_init(|| {
        let public_key: PublicKey = SORA_PROFILE_STREAM_PUBLIC_KEY
            .parse()
            .expect("sora profile streaming public key should parse");
        let private_key: PrivateKey = SORA_PROFILE_STREAM_PRIVATE_KEY
            .parse()
            .expect("sora profile streaming private key should parse");
        KeyPair::new(public_key, private_key).expect("sora profile streaming keypair should match")
    });
    let soranet_transport_keypair = SORA_PROFILE_SORANET_TRANSPORT_KEYPAIR
        .get_or_init(|| checked_soranet_transport_key_pair_from_seed(b"sora-profile".to_vec()));
    let p2p_literal = socket_addr!(127.0.0.1:1337).to_literal();
    let torii_literal = socket_addr!(127.0.0.1:8080).to_literal();
    let mut table = Table::new()
        .write("chain", chain_id().to_string())
        .write("public_key", bls_keypair.public_key().to_string())
        .write(
            "private_key",
            ExposedPrivateKey(bls_keypair.private_key().clone()).to_string(),
        )
        .write(
            "soranet_transport_public_key",
            soranet_transport_keypair.public_key().to_string(),
        )
        .write(
            "soranet_transport_private_key",
            ExposedPrivateKey(soranet_transport_keypair.private_key().clone()).to_string(),
        )
        .write(
            ["streaming", "identity_public_key"],
            streaming_keypair.public_key().to_string(),
        )
        .write(
            ["streaming", "identity_private_key"],
            ExposedPrivateKey(streaming_keypair.private_key().clone()).to_string(),
        )
        .write(["network", "address"], p2p_literal.clone())
        .write(["network", "public_address"], p2p_literal)
        .write(["torii", "address"], torii_literal)
        .write(
            ["genesis", "public_key"],
            SAMPLE_GENESIS_ACCOUNT_KEYPAIR.public_key().to_string(),
        );
    ensure_non_runtime_genesis_expected_hash_for_config_projection(&mut table);
    ensure_sora_profile_trusted_peer_pop(&mut table);
    table
}
fn apply_identity_defaults_for_detection(merged: &mut Table) {
    // Profile detection does not depend on the streaming or SoraNet transport identities, but
    // config parsing does. Force distinct deterministic Ed25519 keys so the BLS node identity
    // never leaks into either transport-specific role during profile projection.
    let mut streaming = match merged.remove("streaming") {
        Some(Value::Table(table)) => table,
        _ => Table::new(),
    };
    streaming.insert(
        "identity_public_key".into(),
        Value::String(SORA_PROFILE_STREAM_PUBLIC_KEY.to_string()),
    );
    streaming.insert(
        "identity_private_key".into(),
        Value::String(SORA_PROFILE_STREAM_PRIVATE_KEY.to_string()),
    );
    merged.insert("streaming".into(), Value::Table(streaming));
    let soranet_transport_keypair = SORA_PROFILE_SORANET_TRANSPORT_KEYPAIR
        .get_or_init(|| checked_soranet_transport_key_pair_from_seed(b"sora-profile".to_vec()));
    merged.insert(
        "soranet_transport_public_key".into(),
        Value::String(soranet_transport_keypair.public_key().to_string()),
    );
    merged.insert(
        "soranet_transport_private_key".into(),
        Value::String(
            ExposedPrivateKey(soranet_transport_keypair.private_key().clone()).to_string(),
        ),
    );
}
/// Materialize only omitted harness-owned account literals for the selected config profile.
/// The global defaults retain their stable Sora literals; explicit user values remain exact.
fn materialize_profile_account_defaults(config_layers: &mut Vec<Table>) -> Result<u16> {
    use iroha_config::parameters::defaults;

    fn missing(table: &Table, path: &[&str]) -> bool {
        let mut table = table;
        for (index, key) in path.iter().enumerate() {
            match table.get(*key) {
                None => return true,
                Some(_) if index + 1 == path.len() => return false,
                Some(Value::Table(next)) => table = next,
                // Do not repair an explicitly malformed user table either.
                Some(_) => return false,
            }
        }
        false
    }
    fn account<const N: usize>(
        merged: &Table,
        layer: &mut Table,
        path: [&'static str; N],
        identity: AccountId,
        discriminant: u16,
    ) -> Result<()> {
        if missing(merged, &path) {
            let literal = identity
                .to_i105_for_discriminant(discriminant)
                .map_err(|error| eyre!("cannot render harness profile account: {error}"))?;
            TomlWriter::new(layer).write(path, literal);
        }
        Ok(())
    }

    let mut merged = Table::new();
    for layer in config_layers.iter() {
        merge_tables(&mut merged, layer);
    }
    let discriminant = match merged.get("chain_discriminant") {
        None => defaults::common::chain_discriminant(),
        Some(value) => u16::try_from(
            value
                .as_integer()
                .ok_or_else(|| eyre!("test-network chain_discriminant must be an integer"))?,
        )
        .map_err(|_| eyre!("test-network chain_discriminant must fit u16"))?,
    };
    let mut layer = Table::new();
    for (field, identity) in [
        (
            "citizenship_escrow_account",
            defaults::governance::citizenship_escrow_account_id(),
        ),
        (
            "bond_escrow_account",
            defaults::governance::bond_escrow_account_id(),
        ),
        (
            "slash_receiver_account",
            defaults::governance::slash_receiver_account_id(),
        ),
        (
            "viral_incentive_pool_account",
            defaults::governance::slash_receiver_account_id(),
        ),
        (
            "viral_escrow_account",
            defaults::governance::slash_receiver_account_id(),
        ),
        (
            "sorafs_pin_fee_treasury_account",
            defaults::governance::sorafs_pin_fee::treasury_account_id(),
        ),
    ] {
        account(&merged, &mut layer, ["gov", field], identity, discriminant)?;
    }
    // The disabled VPN profile still parses its account. Preserve the default identity,
    // rendered for this profile, without enabling VPN or installing a signer.
    account(
        &merged,
        &mut layer,
        ["network", "soranet_vpn", "operator_account_id"],
        defaults::governance::bond_escrow_account_id(),
        discriminant,
    )?;
    account(
        &merged,
        &mut layer,
        ["nexus", "fees", "sponsor_vault_custody_account_id"],
        defaults::nexus::fees::sponsor_vault_custody_account_id(),
        discriminant,
    )?;
    // Telemetry submitter/provider-owner defaults are empty. Explicit entries are
    // deliberately left to the strict selected-chain parser, never translated here.
    if !layer.is_empty() {
        config_layers.push(layer);
    }
    Ok(discriminant)
}

fn merged_sora_profile_detection_config(config_layers: &[Table]) -> Table {
    let mut merged = sora_profile_detection_defaults();
    for layer in config_layers {
        merge_tables(&mut merged, layer);
    }
    apply_identity_defaults_for_detection(&mut merged);
    ensure_sora_profile_trusted_peer_pop(&mut merged);
    merged
}
fn typed_sora_profile_requirements(merged: &Table) -> Result<bool> {
    // Keep the exact selected namespaces, including malformed values for their original reader.
    let mut selected = Table::new();
    for name in ["chain_discriminant", "nexus", "sorafs"] {
        if let Some(value) = merged.get(name) {
            selected.insert(name.to_string(), value.clone());
        }
    }
    let mut reader = ConfigReader::new()
        .with_env(MockEnv::default())
        .with_toml_source(TomlSource::inline(selected));
    let chain_discriminant = reader
        .read_parameter::<u16>(["chain_discriminant"])
        .value_or_else(iroha_config::parameters::defaults::common::chain_discriminant)
        .finish();
    let nexus = reader.read_nested::<iroha_config::parameters::user::Nexus>("nexus");
    let sorafs = reader.read_nested::<iroha_config::parameters::user::Sorafs>("sorafs");
    reader
        .into_result()
        .map_err(|err| eyre!("failed to read Sora profile policy fields: {err:?}"))?;
    let sorafs = sorafs.unwrap();
    let services = sorafs.storage.enabled
        || sorafs.discovery.discovery_enabled
        || sorafs.repair.enabled
        || sorafs.gc.enabled;
    let _account_address_scope = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        chain_discriminant.unwrap(),
    );
    let mut emitter = iroha_config::base::util::Emitter::new();
    let nexus = nexus.unwrap().parse(&mut emitter);
    emitter
        .into_result()
        .map_err(|err| eyre!("failed to parse Sora profile Nexus policy: {err:?}"))?;
    let nexus =
        nexus.ok_or_else(|| eyre!("Sora profile Nexus policy did not produce a configuration"))?;
    Ok(services || nexus.uses_multilane_catalogs() || nexus.has_lane_overrides())
}
fn config_requires_sora_profile(config_layers: &[Table]) -> bool {
    // Inspect the same typed Nexus geometry without requiring unrelated runtime services.
    let merged = merged_sora_profile_detection_config(config_layers);
    let raw_sorafs_storage = read_bool(&merged, &["torii", "sorafs", "storage", "enabled"])
        .unwrap_or(false)
        || read_bool(&merged, &["sorafs", "storage", "enabled"]).unwrap_or(false);
    let raw_sorafs_discovery = read_bool(
        &merged,
        &["torii", "sorafs", "discovery", "discovery_enabled"],
    )
    .unwrap_or(false)
        || read_bool(&merged, &["sorafs", "discovery", "discovery_enabled"]).unwrap_or(false);
    let raw_sorafs_repair = read_bool(&merged, &["torii", "sorafs", "repair", "enabled"])
        .unwrap_or(false)
        || read_bool(&merged, &["sorafs", "repair", "enabled"]).unwrap_or(false);
    let raw_sorafs_gc = read_bool(&merged, &["torii", "sorafs", "gc", "enabled"]).unwrap_or(false)
        || read_bool(&merged, &["sorafs", "gc", "enabled"]).unwrap_or(false);
    match typed_sora_profile_requirements(&merged) {
        Ok(required) => {
            required
                || raw_sorafs_storage
                || raw_sorafs_discovery
                || raw_sorafs_repair
                || raw_sorafs_gc
        }
        Err(err) => {
            warn!(
                ?err,
                "failed to read typed Sora profile fields; runtime parsing will reject invalid configuration"
            );
            // Service flags remain observable, but field presence alone is never a Nexus override.
            raw_sorafs_storage || raw_sorafs_discovery || raw_sorafs_repair || raw_sorafs_gc
        }
    }
}

#[cfg(test)]
fn sora_profile_runtime_config_fixture(
    config_layers: &[Table],
) -> (tempfile::TempDir, NetworkPeer, Table) {
    let directory = tempfile::tempdir().expect("temporary private Sora-profile peer");
    let environment = Environment {
        dir: directory.path().to_path_buf(),
    };
    let peer = NetworkPeer::builder().build(&environment);
    let mut merged = sora_profile_detection_defaults();
    // Preserve the original detection identities and PoP roster for full-runtime parsing.
    for layer in config_layers {
        merge_tables(&mut merged, layer);
    }
    apply_identity_defaults_for_detection(&mut merged);
    ensure_sora_profile_trusted_peer_pop(&mut merged);
    (directory, peer, merged)
}
#[cfg(test)]
fn resolve_actual_config(
    peer: &NetworkPeer,
    config_layers: &[Table],
) -> Option<iroha_config::parameters::actual::Root> {
    match resolve_actual_config_result(peer, config_layers) {
        Ok(config) => Some(config),
        Err(err) => {
            warn!(?err, "failed to parse merged config for genesis config");
            None
        }
    }
}
fn resolve_actual_config_result(
    peer: &NetworkPeer,
    config_layers: &[Table],
) -> Result<iroha_config::parameters::actual::Root> {
    let mut merged = peer.base_config_table();
    for layer in config_layers {
        merge_tables(&mut merged, layer);
    }
    parse_actual_config_for_genesis_result(merged, config_layers)
}
fn resolve_final_actual_config(
    peer: &NetworkPeer,
    config_layers: &[Table],
) -> iroha_config::parameters::actual::Root {
    resolve_actual_config_result(peer, config_layers).unwrap_or_else(|error| {
        panic!(
            "final fully merged test-network config for peer `{}` is invalid: {error:#}",
            peer.mnemonic()
        )
    })
}
fn resolve_kura_store_dir(
    peer: &NetworkPeer,
    config_layers: &[Table],
) -> Result<(PathBuf, String, String)> {
    let config = resolve_actual_config_result(peer, config_layers).wrap_err_with(|| {
        format!(
            "failed to resolve Kura storage from peer `{}` config",
            peer.mnemonic()
        )
    })?;
    let (store_dir, origin) = config.kura.store_dir.into_tuple();
    let value = store_dir.to_string_lossy().to_string();
    let resolved = if store_dir.is_absolute() {
        store_dir
    } else {
        peer.dir.join(store_dir)
    };
    Ok((resolved, parameter_origin_to_string(&origin), value))
}
// The peer's original fixture launch plus absent safety history authorizes the first-key
// assertion. This owner survives restarts; disappearance of either file never renews it.
fn first_consensus_boot(run: usize, records: &Path, installation_log: &Path) -> Result<bool> {
    if run != 1 {
        return Ok(false);
    }
    for path in [records, installation_log] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!("failed to inspect consensus history {}", path.display())
                });
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
fn parse_actual_config_for_genesis(
    merged: Table,
    config_layers: &[Table],
) -> Option<iroha_config::parameters::actual::Root> {
    match parse_actual_config_for_genesis_result(merged, config_layers) {
        Ok(config) => Some(config),
        Err(err) => {
            warn!(?err, "failed to parse merged config for genesis config");
            None
        }
    }
}
fn parse_actual_config_for_genesis_result(
    mut merged: Table,
    config_layers: &[Table],
) -> Result<iroha_config::parameters::actual::Root> {
    ensure_non_runtime_genesis_expected_hash_for_config_projection(&mut merged);
    let reader = ConfigReader::new()
        .with_env(MockEnv::default())
        .with_toml_source(TomlSource::inline(merged));
    let sora_profile = iroha_config::sora_profile::SoraProfileSelection::from_reader(&reader);
    let user = reader
        .read_and_complete::<iroha_config::parameters::user::Root>()
        .map_err(|err| eyre!("failed to read merged config for genesis config: {err:?}"))?;
    let mut config = user
        .parse()
        .map_err(|err| eyre!("failed to parse merged config for genesis config: {err:?}"))?;
    if config_requires_sora_profile(config_layers) {
        sora_profile.apply(&mut config);
    }
    config.apply_storage_budget();
    Ok(config)
}
#[cfg(test)]
fn resolve_da_proof_policies(
    peer: &NetworkPeer,
    config_layers: &[Table],
) -> Option<DaProofPolicyBundle> {
    resolve_actual_config(peer, config_layers)
        .map(|config| iroha_core::da::proof_policy_bundle(&config.nexus.lane_config))
}
fn get_nested_value<'a>(table: &'a Table, path: &[&str]) -> Option<&'a Value> {
    if path.is_empty() {
        return None;
    }
    let mut current = table.get(path[0])?;
    for segment in &path[1..] {
        current = current.as_table()?.get(*segment)?;
    }
    Some(current)
}
fn read_bool(table: &Table, path: &[&str]) -> Option<bool> {
    get_nested_value(table, path).and_then(Value::as_bool)
}
fn replace_consensus_handshake_meta(genesis_isi: &mut Vec<Vec<InstructionBox>>) -> bool {
    let mut was_replaced = false;
    genesis_isi.iter_mut().for_each(|instructions| {
        let original_len = instructions.len();
        instructions.retain(|instruction| {
            let is_handshake_meta = instruction
                .as_any()
                .downcast_ref::<SetParameter>()
                .is_some_and(|set_param| {
                    matches!(
                        set_param.inner(),
                        Parameter::Custom(custom)
                            if custom.id() == &consensus_metadata::handshake_meta_id()
                    )
                });
            if is_handshake_meta {
                was_replaced = true;
            }
            !is_handshake_meta
        });
        if instructions.is_empty() && original_len > 0 {
            instructions.shrink_to_fit();
        }
    });
    was_replaced
}
fn consensus_parameters_from_genesis(
    genesis: &GenesisBlock,
) -> iroha_data_model::parameter::Parameters {
    let mut parameter_state = iroha_data_model::parameter::Parameters::default();
    for tx in genesis.0.external_transactions() {
        if let Executable::Instructions(instructions) = tx.instructions() {
            for instruction in instructions {
                if let Some(set_param) = instruction.as_any().downcast_ref::<SetParameter>() {
                    parameter_state.set_parameter(set_param.inner().clone());
                }
            }
        }
    }
    parameter_state
}
fn consensus_parameters_from_genesis_with_overrides(
    genesis: &GenesisBlock,
    genesis_isi: &[Vec<InstructionBox>],
    genesis_post_topology_isi: &[Vec<InstructionBox>],
) -> iroha_data_model::parameter::Parameters {
    let mut parameters = consensus_parameters_from_genesis(genesis);
    for instruction in genesis_isi
        .iter()
        .chain(genesis_post_topology_isi)
        .flat_map(|batch| batch.iter())
    {
        let Some(set_parameter) = instruction.as_any().downcast_ref::<SetParameter>() else {
            continue;
        };
        if matches!(
            set_parameter.inner(),
            Parameter::Custom(custom)
                if custom.id() == &consensus_metadata::handshake_meta_id()
        ) {
            continue;
        }
        parameters.set_parameter(set_parameter.inner().clone());
    }
    parameters
}
fn genesis_instructions_contain_consensus_handshake_meta(
    genesis_isi: &[Vec<InstructionBox>],
    consensus_handshake_meta: &Parameter,
) -> bool {
    let expected_meta = match consensus_handshake_meta {
        Parameter::Custom(custom) if custom.id() == &consensus_metadata::handshake_meta_id() => {
            custom
        }
        _ => return false,
    };
    genesis_isi
        .iter()
        .flat_map(|tx| tx.iter())
        .any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<SetParameter>()
                .is_some_and(|set_param| match set_param.inner() {
                    Parameter::Custom(custom) => custom == expected_meta,
                    _ => false,
                })
        })
}
fn genesis_has_exactly_one_consensus_handshake(block: &GenesisBlock, expected: &Parameter) -> bool {
    let expected_meta = match expected {
        Parameter::Custom(custom) if custom.id() == &consensus_metadata::handshake_meta_id() => {
            custom
        }
        _ => return false,
    };
    let mut handshakes = block
        .0
        .external_transactions()
        .filter_map(|tx| match tx.instructions() {
            Executable::Instructions(instructions) => Some(instructions),
            _ => None,
        })
        .flat_map(|instructions| instructions.iter())
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set_param| match set_param.inner() {
            Parameter::Custom(custom)
                if custom.id() == &consensus_metadata::handshake_meta_id() =>
            {
                Some(custom)
            }
            _ => None,
        });
    matches!(handshakes.next(), Some(actual) if actual == expected_meta)
        && handshakes.next().is_none()
}
fn genesis_contains_any_consensus_handshake(block: &GenesisBlock) -> bool {
    block
        .0
        .external_transactions()
        .any(|tx| match tx.instructions() {
            Executable::Instructions(instructions) => instructions.iter().any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<SetParameter>()
                    .is_some_and(|set_param| {
                        matches!(
                            set_param.inner(),
                            Parameter::Custom(custom)
                                if custom.id() == &consensus_metadata::handshake_meta_id()
                        )
                    })
            }),
            _ => false,
        })
}
#[path = "lib/genesis_parameter_normalization.rs"]
mod genesis_parameter_normalization;
use genesis_parameter_normalization::normalize_genesis_parameters;
fn consensus_handshake_parameter(consensus_profile: &ConsensusBootstrapProfile) -> Parameter {
    let mode = match consensus_profile.params.mode {
        ConsensusGenesisModeParams::Permissioned => SumeragiConsensusMode::Permissioned,
        ConsensusGenesisModeParams::Npos(_) => SumeragiConsensusMode::Npos,
    };
    let metadata = ConsensusHandshakeMetadata {
        mode,
        block_cadence_ms: consensus_profile.params.block_cadence_ms,
        wire_protocol_version: consensus_profile.wire_protocol_version,
        consensus_fingerprint: ConsensusFingerprint::new(consensus_profile.fingerprint()),
        sumeragi_context: consensus_profile.params.sumeragi_context.clone(),
    };
    metadata
        .validate()
        .expect("test-network handshake metadata must be canonical");
    let metadata =
        norito::json::value::to_value(&metadata).expect("serialize canonical handshake metadata");
    let handshake_payload =
        Json::from_norito_value_ref(&metadata).expect("handshake metadata JSON must serialize");
    Parameter::Custom(CustomParameter::new(
        consensus_metadata::handshake_meta_id(),
        handshake_payload,
    ))
}
fn npos_params_from_genesis(
    genesis_isi: &[Vec<InstructionBox>],
    genesis_post_topology_isi: &[Vec<InstructionBox>],
) -> Result<Option<SumeragiNposParameters>> {
    let target = SumeragiNposParameters::parameter_id();
    let mut snapshots = genesis_isi
        .iter()
        .chain(genesis_post_topology_isi)
        .flat_map(|tx| tx.iter())
        .filter_map(|instruction| instruction.as_any().downcast_ref::<SetParameter>())
        .filter_map(|set_param| match set_param.inner() {
            Parameter::Custom(custom) if custom.id() == &target => Some(custom),
            _ => None,
        });
    let Some(snapshot) = snapshots.next() else {
        return Ok(None);
    };
    if snapshots.next().is_some() {
        return Err(eyre!(
            "genesis must contain exactly one `sumeragi_npos_parameters` snapshot"
        ));
    }
    Ok(SumeragiNposParameters::from_custom_parameter(snapshot)?)
}
fn authenticated_validator_capacity(
    declared_capacity: usize,
    consensus_mode: ConsensusMode,
    genesis_isi: &[Vec<InstructionBox>],
    genesis_post_topology_isi: &[Vec<InstructionBox>],
) -> Result<usize> {
    if consensus_mode == ConsensusMode::Permissioned {
        return Ok(declared_capacity);
    }
    let npos =
        npos_params_from_genesis(genesis_isi, genesis_post_topology_isi)?.unwrap_or_default();
    npos.validate()
        .map_err(|error| eyre!("invalid signed NPoS validator ceiling: {error}"))?;
    let signed_capacity = usize::try_from(npos.max_validators())
        .map_err(|_| eyre!("signed NPoS maximum validator roster does not fit this platform"))?;
    Ok(declared_capacity.max(signed_capacity))
}
fn resolve_npos_bootstrap_stake(
    genesis_isi: &[Vec<InstructionBox>],
    genesis_post_topology_isi: &[Vec<InstructionBox>],
    requested: Quantity,
) -> Quantity {
    let min_self_bond = npos_params_from_genesis(genesis_isi, genesis_post_topology_isi)
        .expect("NPoS genesis snapshot must be valid")
        .expect("NPoS genesis snapshot must be present before stake bootstrap")
        .min_self_bond()
        .clone();
    requested.max(min_self_bond)
}
impl Default for NetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}
/// Test network builder
impl NetworkBuilder {
    /// Constructor
    pub fn new() -> Self {
        init_logger_once();
        init_instruction_registry();
        // Default to a fast signed localnet cadence; callers can explicitly use
        // the protocol default when timing fidelity matters more than test speed.
        let mut builder = Self {
            n_peers: DEFAULT_NETWORK_PEERS,
            max_validator_capacity: None,
            committee_validator_p2p_bootstrap: None,
            observer_p2p_bootstrap: None,
            observer_slow_reader_relays: None,
            config_layers: vec![],
            block_cadence: Some(LOCALNET_BLOCK_CADENCE),
            sync_timeout: None,
            peer_startup_timeout: None,
            ivm_fuel: IvmFuelConfig::Auto,
            genesis_isi: vec![vec![]],
            genesis_post_topology_isi: Vec::new(),
            custom_genesis: None,
            seed: None,
            genesis_key_pair: SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone(),
            block_sync_gossip_period: DEFAULT_BLOCK_SYNC,
            consensus_mode: ConsensusMode::Permissioned,
            auto_populate_trusted_peer_pops: true,
            genesis_committee_keys_for_global_peers: false,
            npos_genesis_bootstrap_stake: Some(
                SumeragiNposParameters::default().min_self_bond().clone(),
            ),
            private_settlement_route_control: false,
            parliament_test_signers: None,
            topology_genesis_isi: Vec::new(),
        };
        let mut default_layer = Table::new();
        let mut writer = TomlWriter::new(&mut default_layer);
        // Scale per-peer thread pools to avoid oversubscribing the host when many
        // test networks run in parallel, but keep a minimum to prevent stalls.
        let concurrency_threads =
            i64::try_from(test_concurrency_threads()).expect("test concurrency threads fit in i64");
        writer
            .write(
                ["concurrency", "scheduler_min_threads"],
                concurrency_threads,
            )
            .write(
                ["concurrency", "scheduler_max_threads"],
                concurrency_threads,
            )
            .write(["concurrency", "rayon_global_threads"], concurrency_threads)
            .write(["pipeline", "workers"], concurrency_threads);
        builder.config_layers.push(default_layer);
        builder
    }
    /// Set the exact revision-4 `3f + 1` validator count for the network.
    ///
    /// Four by default. Invalid or out-of-range committee sizes panic before
    /// any peer, signed genesis, or runtime configuration is constructed. Once
    /// a feature-isolated Parliament signer fixture is selected, every count
    /// other than its exact four-validator roster also panics.
    pub fn with_peers(mut self, n_peers: usize) -> Self {
        assert!(
            is_valid_committee_size(n_peers),
            "validator peer count must be an exact revision-4 3f + 1 committee in {MIN_VALIDATORS_PER_HEIGHT}..={MAX_VALIDATORS_PER_HEIGHT}, got {n_peers}"
        );
        if let Some(selection) = &self.parliament_test_signers {
            assert_eq!(
                n_peers, PARLIAMENT_TEST_SIGNER_VALIDATOR_COUNT,
                "the feature-isolated Parliament signer fixture requires exactly four validators",
            );
            if let ParliamentTestSignerSelection::PerPeer(modes) = selection {
                assert_eq!(
                    modes.len(),
                    n_peers,
                    "Parliament beacon signer modes must name every validator exactly once",
                );
            }
        }
        if let Some(max_validator_capacity) = self.max_validator_capacity {
            assert!(
                n_peers <= max_validator_capacity,
                "validator peer count {n_peers} exceeds the reserved maximum validator capacity {max_validator_capacity}"
            );
        }
        let committee_validator_count = self
            .committee_validator_p2p_bootstrap
            .map_or(0, CommitteeValidatorP2pBootstrap::validator_count);
        if let Some(bootstrap) = self.observer_p2p_bootstrap {
            bootstrap
                .validate_for_validators(
                    self.max_validator_capacity
                        .unwrap_or(n_peers)
                        .checked_add(committee_validator_count)
                        .expect("validator participant count cannot overflow"),
                    ObserverP2pBootstrap::connection_capacity(),
                )
                .unwrap_or_else(|error| {
                    panic!("invalid observer bootstrap after peer change: {error}")
                });
        }
        if let Some(bootstrap) = self.committee_validator_p2p_bootstrap {
            bootstrap
                .validate_for_network(
                    self.max_validator_capacity.unwrap_or(n_peers),
                    self.observer_p2p_bootstrap
                        .map_or(0, ObserverP2pBootstrap::observer_count),
                    CommitteeValidatorP2pBootstrap::connection_capacity(),
                )
                .unwrap_or_else(|error| {
                    panic!("invalid committee-validator bootstrap after peer change: {error}")
                });
        }
        self.n_peers = n_peers;
        self
    }
    /// Add configured Validator processes for non-global participant committees.
    ///
    /// These peers join the trusted P2P fanout and receive the signed genesis,
    /// but are excluded from [`Self::with_peers`], the global genesis topology,
    /// and global quorum calculations. They start alongside the global roster
    /// with a bounded stagger and retain the Validator runtime role. On-chain
    /// participant eligibility also requires a live Committee consensus-key record.
    ///
    /// # Errors
    /// Returns an error when all configured processes cannot fit full localnet
    /// fanout under the production core P2P connection cap.
    pub fn with_committee_validator_p2p_bootstrap(
        mut self,
        bootstrap: CommitteeValidatorP2pBootstrap,
    ) -> std::result::Result<Self, CommitteeValidatorP2pBootstrapError> {
        assert!(
            self.parliament_test_signers.is_none(),
            "supplementary committee validators are unsupported by the feature-isolated Parliament signer daemon"
        );
        bootstrap.validate_for_network(
            self.max_validator_capacity.unwrap_or(self.n_peers),
            self.observer_p2p_bootstrap
                .map_or(0, ObserverP2pBootstrap::observer_count),
            CommitteeValidatorP2pBootstrap::connection_capacity(),
        )?;
        self.committee_validator_p2p_bootstrap = Some(bootstrap);
        Ok(self)
    }
    /// Add a bounded set of signed, non-voting observer replicas.
    ///
    /// Observers become trusted P2P participants but are excluded from genesis
    /// topology and `trusted_peers_pop`. Their private keys stay owned by the
    /// generated [`NetworkPeer`] values.
    ///
    /// # Errors
    /// Returns an error when the current or pre-reserved validator count plus
    /// observers cannot fit a full localnet fanout under the production core
    /// P2P connection cap.
    pub fn with_observer_p2p_bootstrap(
        mut self,
        bootstrap: ObserverP2pBootstrap,
    ) -> std::result::Result<Self, ObserverP2pBootstrapError> {
        let committee_validator_count = self
            .committee_validator_p2p_bootstrap
            .map_or(0, CommitteeValidatorP2pBootstrap::validator_count);
        bootstrap.validate_for_validators(
            self.max_validator_capacity
                .unwrap_or(self.n_peers)
                .checked_add(committee_validator_count)
                .ok_or(ObserverP2pBootstrapError::ParticipantCountOverflow {
                    validators: self.max_validator_capacity.unwrap_or(self.n_peers),
                    observers: bootstrap.observer_count(),
                })?,
            ObserverP2pBootstrap::connection_capacity(),
        )?;
        self.observer_p2p_bootstrap = Some(bootstrap);
        Ok(self)
    }
    /// Route every signed observer through a bounded transparent slow-reader relay.
    ///
    /// The hook is intended for P2P backpressure integration tests. Relay
    /// addresses replace observer listener addresses in all shared trusted-peer
    /// layers, while encrypted production traffic is forwarded unchanged.
    ///
    /// # Errors
    /// Returns an error unless [`Self::with_observer_p2p_bootstrap`] was called
    /// first.
    pub fn with_observer_slow_reader_relays(
        mut self,
        config: ObserverSlowReaderRelayConfig,
    ) -> std::result::Result<Self, ObserverSlowReaderRelayError> {
        if self.observer_p2p_bootstrap.is_none() {
            return Err(ObserverSlowReaderRelayError::MissingObserverBootstrap);
        }
        self.observer_slow_reader_relays = Some(config);
        Ok(self)
    }
    /// Use a dedicated test daemon with authenticated private-settlement HTTP route control.
    pub fn with_private_settlement_route_control(mut self) -> Self {
        assert!(
            self.parliament_test_signers.is_none(),
            "the feature-isolated Parliament signer has a separate daemon binary"
        );
        self.private_settlement_route_control = true;
        self
    }
    /// Use a separately built, feature-isolated daemon whose runtime dependency
    /// returns one proof-valid global-beacon share and one proof-valid TLE share
    /// for each validator's exact local seat. Consensus and release validation
    /// remain unchanged.
    ///
    /// # Panics
    ///
    /// Panics when private-settlement route control is already selected or the builder does not
    /// name the fixture's exact four-validator roster.
    pub fn with_parliament_test_signers(mut self) -> Self {
        assert!(
            !self.private_settlement_route_control,
            "the Parliament signer and private-settlement-route-control daemons are separate test binaries"
        );
        assert_eq!(
            self.n_peers, PARLIAMENT_TEST_SIGNER_VALIDATOR_COUNT,
            "the feature-isolated Parliament signer fixture requires exactly four validators",
        );
        assert!(
            self.committee_validator_p2p_bootstrap.is_none(),
            "the feature-isolated Parliament signer daemon does not support supplementary committee validators",
        );
        self.parliament_test_signers = Some(ParliamentTestSignerSelection::AllValid);
        self
    }

    /// Use the feature-isolated Parliament daemon with one exact beacon signer
    /// mode for every validator, while keeping every TLE signer proof-valid.
    ///
    /// # Panics
    ///
    /// Panics before network construction when private-settlement route control was selected or
    /// when the builder does not name exactly four validators or `modes` does
    /// not contain exactly one entry for each validator.
    pub fn with_parliament_beacon_signer_modes(
        mut self,
        modes: impl IntoIterator<Item = ParliamentBeaconSignerMode>,
    ) -> Self {
        assert!(
            !self.private_settlement_route_control,
            "the Parliament signer and private-settlement-route-control daemons are separate test binaries"
        );
        assert_eq!(
            self.n_peers, PARLIAMENT_TEST_SIGNER_VALIDATOR_COUNT,
            "the feature-isolated Parliament signer fixture requires exactly four validators",
        );
        assert!(
            self.committee_validator_p2p_bootstrap.is_none(),
            "the feature-isolated Parliament signer daemon does not support supplementary committee validators",
        );
        let modes = modes.into_iter().collect::<Vec<_>>();
        assert_eq!(
            modes.len(),
            self.n_peers,
            "Parliament beacon signer modes must name every validator exactly once",
        );
        self.parliament_test_signers = Some(ParliamentTestSignerSelection::PerPeer(modes));
        self
    }
    /// Ensure the network has the smallest revision-4 committee with at least `min_peers` peers.
    ///
    /// Values between valid committee sizes round up. A zero minimum or a
    /// minimum above the protocol ceiling panics before construction. When a
    /// feature-isolated Parliament signer fixture is selected, a minimum that
    /// rounds to any count other than four also panics.
    pub fn with_min_peers(mut self, min_peers: usize) -> Self {
        assert_ne!(min_peers, 0);
        let target_peers = revision4_committee_at_least(min_peers).unwrap_or_else(|| {
            panic!(
                "minimum validator peer count must not exceed revision-4 ceiling {MAX_VALIDATORS_PER_HEIGHT}, got {min_peers}"
            )
        });
        if self.parliament_test_signers.is_some() {
            assert_eq!(
                target_peers, PARLIAMENT_TEST_SIGNER_VALIDATOR_COUNT,
                "the feature-isolated Parliament signer fixture requires exactly four validators",
            );
        }
        if let Some(max_validator_capacity) = self.max_validator_capacity {
            assert!(
                target_peers <= max_validator_capacity,
                "minimum validator peer count {target_peers} exceeds the reserved maximum validator capacity {max_validator_capacity}"
            );
        }
        if self.n_peers < target_peers {
            let committee_validator_count = self
                .committee_validator_p2p_bootstrap
                .map_or(0, CommitteeValidatorP2pBootstrap::validator_count);
            if let Some(bootstrap) = self.observer_p2p_bootstrap {
                bootstrap
                    .validate_for_validators(
                        self.max_validator_capacity
                            .unwrap_or(target_peers)
                            .checked_add(committee_validator_count)
                            .expect("validator participant count cannot overflow"),
                        ObserverP2pBootstrap::connection_capacity(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("invalid observer bootstrap after minimum peer change: {error}")
                    });
            }
            if let Some(bootstrap) = self.committee_validator_p2p_bootstrap {
                bootstrap
                    .validate_for_network(
                        self.max_validator_capacity.unwrap_or(target_peers),
                        self.observer_p2p_bootstrap
                            .map_or(0, ObserverP2pBootstrap::observer_count),
                        CommitteeValidatorP2pBootstrap::connection_capacity(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("invalid committee-validator bootstrap after minimum peer change: {error}")
                    });
            }
            self.n_peers = target_peers;
        }
        self
    }
    /// Reserve static Sumeragi capacity for a future validator roster.
    ///
    /// This does not add peers or PoPs to the bootstrap roster. It raises the
    /// generated queue capacity so already-running validators can safely admit
    /// later [`RegisterPeerWithPop`](iroha_data_model::isi::register::RegisterPeerWithPop)
    /// instructions up to `max_validator_capacity`.
    ///
    /// # Panics
    ///
    /// Panics when the reservation is smaller than the bootstrap validator
    /// count, exceeds the protocol validator limit, or cannot retain an
    /// already-configured observer fanout.
    pub fn with_max_validator_capacity(mut self, max_validator_capacity: usize) -> Self {
        assert!(
            max_validator_capacity >= self.n_peers,
            "maximum validator capacity {max_validator_capacity} must cover all {} bootstrap validators",
            self.n_peers
        );
        assert!(
            max_validator_capacity <= MAX_VALIDATORS_PER_HEIGHT,
            "maximum validator capacity must not exceed protocol ceiling {MAX_VALIDATORS_PER_HEIGHT}, got {max_validator_capacity}"
        );
        if let Some(bootstrap) = self.observer_p2p_bootstrap {
            let committee_validator_count = self
                .committee_validator_p2p_bootstrap
                .map_or(0, CommitteeValidatorP2pBootstrap::validator_count);
            bootstrap
                .validate_for_validators(
                    max_validator_capacity
                        .checked_add(committee_validator_count)
                        .expect("validator participant count cannot overflow"),
                    ObserverP2pBootstrap::connection_capacity(),
                )
                .unwrap_or_else(|error| {
                    panic!("invalid observer bootstrap after validator reservation: {error}")
                });
        }
        if let Some(bootstrap) = self.committee_validator_p2p_bootstrap {
            bootstrap
                .validate_for_network(
                    max_validator_capacity,
                    self.observer_p2p_bootstrap
                        .map_or(0, ObserverP2pBootstrap::observer_count),
                    CommitteeValidatorP2pBootstrap::connection_capacity(),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "invalid committee-validator bootstrap after validator reservation: {error}"
                    )
                });
        }
        self.max_validator_capacity = Some(max_validator_capacity);
        self
    }
    /// Override the peer startup timeout for this network instance.
    ///
    /// Use this for slow hosts or heavy fixtures when peer bootstrap may exceed environment-level
    /// defaults. The timeout must be strictly positive.
    pub fn with_peer_startup_timeout(mut self, timeout: Duration) -> Self {
        assert!(timeout > Duration::ZERO, "startup timeout must be positive");
        self.peer_startup_timeout = Some(timeout);
        self
    }
    /// Override the block-sync / height-convergence timeout for this network instance.
    ///
    /// Use this for heavier fixtures whose end-to-end block convergence may exceed the
    /// environment-level default. The timeout must be strictly positive.
    pub fn with_sync_timeout(mut self, timeout: Duration) -> Self {
        assert!(timeout > Duration::ZERO, "sync timeout must be positive");
        self.sync_timeout = Some(timeout);
        self
    }
    /// Set the signed immutable consensus block cadence.
    ///
    /// # Panics
    /// - If `duration` is shorter than [`MIN_BLOCK_CADENCE_MS`] milliseconds.
    /// - If `duration` exceeds `u64::MAX` milliseconds (cannot be encoded in genesis parameters).
    pub fn with_block_cadence(mut self, duration: Duration) -> Self {
        let cadence_ms = duration.as_millis();
        assert!(
            cadence_ms >= u128::from(MIN_BLOCK_CADENCE_MS),
            "block cadence must be at least {MIN_BLOCK_CADENCE_MS} ms (got {cadence_ms} ms)",
        );
        const MAX_BLOCK_CADENCE_MS: u64 = u64::MAX;
        assert!(
            cadence_ms <= u128::from(MAX_BLOCK_CADENCE_MS),
            "block cadence must not exceed {MAX_BLOCK_CADENCE_MS} ms",
        );
        self.block_cadence = Some(duration);
        self
    }
    /// Use the protocol's default signed block cadence.
    pub fn with_default_block_cadence(mut self) -> Self {
        self.block_cadence = None;
        self
    }
    /// Return the explicit signed block cadence, if configured.
    pub fn configured_block_cadence(&self) -> Option<Duration> {
        self.block_cadence
    }
    /// Override the block gossip period used by block sync and gossip topics.
    ///
    /// Increasing the period introduces additional message delay between peers,
    /// which is useful when simulating unstable or high-latency links.
    /// The value must be strictly positive.
    pub fn with_block_sync_gossip_period(mut self, period: Duration) -> Self {
        assert!(
            period > Duration::ZERO,
            "block gossip period must be positive"
        );
        self.block_sync_gossip_period = period;
        self
    }
    /// Select the consensus mode committed by the signed genesis block.
    ///
    /// Consensus mode is protocol state, not a mutable node-local setting. All
    /// validators in a test network therefore receive the same signed genesis
    /// selection regardless of their local configuration layers.
    pub fn with_consensus_mode(mut self, mode: ConsensusMode) -> Self {
        self.consensus_mode = mode;
        self
    }
    /// Select permissioned consensus in the signed genesis block.
    ///
    /// For an otherwise standard generated genesis with exact committee
    /// geometry and no caller-owned authority/support state, the harness also
    /// provisions the trusted validators as active stake-elected authority for
    /// the default public lane. Global permissioned consensus and lane
    /// authority remain separate protocol inputs; custom, manifest-backed, or
    /// explicitly bootstrapped fixtures retain responsibility for their own
    /// lane authority.
    pub fn with_permissioned_consensus(self) -> Self {
        self.with_consensus_mode(ConsensusMode::Permissioned)
    }
    /// Select NPoS consensus in the signed genesis block.
    pub fn with_npos_consensus(self) -> Self {
        self.with_consensus_mode(ConsensusMode::Npos)
    }
    /// Register live Committee-role keys for the global peers in generated genesis.
    ///
    /// Autoscale participant lanes require Committee authority even when their
    /// candidates already vote in global consensus with Validator-role keys.
    pub fn with_genesis_committee_keys_for_global_peers(mut self) -> Self {
        self.genesis_committee_keys_for_global_peers = true;
        self
    }
    /// Automatically generate BLS key material and PoP records for trusted peers.
    ///
    /// Enabled by default; calling this method is only necessary when chaining builder combinators.
    /// The base config layer will include `trusted_peers_pop` entries aligning with the peers
    /// created by the builder.
    pub fn with_auto_populated_trusted_peers(mut self) -> Self {
        self.auto_populate_trusted_peer_pops = true;
        self
    }
    /// Override the NPoS bootstrap stake amount injected into genesis.
    ///
    /// This registers Nexus/IVM domains, a gas account, the default stake asset, and per-peer
    /// validator accounts funded with the stake amount, then activates them. Calling this method
    /// also selects NPoS in the signed genesis consensus profile.
    pub fn with_npos_genesis_bootstrap(mut self, stake_amount: Quantity) -> Self {
        assert!(!stake_amount.is_zero(), "stake_amount must be non-zero");
        self.consensus_mode = ConsensusMode::Npos;
        self.npos_genesis_bootstrap_stake = Some(stake_amount);
        self
    }
    /// Disable the NPoS bootstrap transaction injected into genesis.
    ///
    /// Use this when the caller already provides equivalent validator bootstrap instructions.
    pub fn without_npos_genesis_bootstrap(mut self) -> Self {
        self.npos_genesis_bootstrap_stake = None;
        self
    }
    /// Override the genesis signing key pair used to sign the manifest.
    pub fn with_genesis_keypair(mut self, key_pair: KeyPair) -> Self {
        self.genesis_key_pair = key_pair;
        self
    }
    /// Use the deterministic “real” genesis key material shared with the localnet fixtures.
    pub fn with_real_genesis_keypair(self) -> Self {
        self.with_genesis_keypair(REAL_GENESIS_ACCOUNT_KEYPAIR.clone())
    }
    /// Disable automatic trusted peer PoP entries.
    ///
    /// This is only useful for negative tests that explicitly exercise missing PoP scenarios.
    pub fn without_auto_populated_trusted_peers(mut self) -> Self {
        self.auto_populate_trusted_peer_pops = false;
        self
    }
    /// Add a new TOML configuration _layer_, using [`TomlWriter`] helper.
    ///
    /// Layers are composed using `extends` field in the final config file:
    ///
    /// ```toml
    /// extends = ["layer-1.toml", "layer-2.toml", "layer-3.toml"]
    /// ```
    ///
    /// Thus, layers are merged sequentially, with later ones overriding _conflicting_ parameters from earlier ones.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_test_network::NetworkBuilder;
    ///
    /// NetworkBuilder::new().with_config_layer(|t| {
    ///     t.write(["logger", "level"], "DEBUG");
    /// });
    /// ```
    pub fn with_config_layer<F>(mut self, f: F) -> Self
    where
        for<'a> F: FnOnce(&'a mut TomlWriter<'a>),
    {
        let mut table = Table::new();
        let mut writer = TomlWriter::new(&mut table);
        f(&mut writer);
        self.config_layers.push(table);
        self
    }
    /// Push a pre-built TOML configuration layer.
    pub fn with_config_table(mut self, table: Table) -> Self {
        self.config_layers.push(table);
        self
    }
    /// Append an instruction to the last genesis transaction.
    pub fn with_genesis_instruction(mut self, isi: impl Into<InstructionBox>) -> Self {
        self.genesis_isi
            .last_mut()
            .expect("at least one transaction exists")
            .push(isi.into());
        self
    }
    /// Append a post-topology genesis transaction.
    ///
    /// The provided instructions run after peers/topology are registered.
    pub fn with_genesis_post_topology_isi(mut self, isi: Vec<InstructionBox>) -> Self {
        if !isi.is_empty() {
            self.genesis_post_topology_isi.push(isi);
        }
        self
    }
    /// Append a post-topology genesis transaction whose instructions `build` derives from the
    /// signed voting topology (each peer's id and proof of possession, in topology order), e.g.
    /// a lane policy whose committee is the validators.
    pub fn with_genesis_post_topology_isi_from<F>(mut self, build: F) -> Self
    where
        F: Fn(&[GenesisTopologyEntry]) -> Vec<InstructionBox> + Send + Sync + 'static,
    {
        self.topology_genesis_isi.push(Arc::new(build));
        self
    }
    /// Start a new empty transaction in the genesis block.
    pub fn next_genesis_transaction(mut self) -> Self {
        self.genesis_isi.push(Vec::new());
        self
    }
    /// Override the genesis instructions using a custom block builder.
    ///
    /// The provided closure receives the network topology (as peer IDs) and the
    /// corresponding Proof-of-Possession entries. It must return a signed genesis
    /// block. The harness consolidates source parameters and builder overrides into
    /// one carrier before ordinary instructions, retaining a leading executor upgrade.
    /// It preserves each remaining source payload and ordinary instruction order,
    /// re-signs affected transactions and the block with the configured genesis
    /// key, and pre-executes under the exact final pipeline, Nexus, and ZK runtime
    /// configuration. It then binds the staged Nexus/AMX context and caches the
    /// identical final bytes supplied to every peer. A custom block whose signed
    /// voting roster differs from the guarded builder topology is rejected before
    /// consensus parameters are derived.
    pub fn with_genesis_block<F>(mut self, build: F) -> Self
    where
        F: Fn(UniqueVec<PeerId>, Vec<GenesisTopologyEntry>) -> GenesisBlock + Send + Sync + 'static,
    {
        self.custom_genesis = Some(Arc::new(
            move |topology,
                  topology_entries,
                  _committee_validators,
                  _committee_validator_entries,
                  _observers,
                  _observer_entries| { build(topology, topology_entries) },
        ));
        self.genesis_isi = vec![Vec::new()];
        self
    }
    /// Override genesis using both the voting topology and observer identities.
    ///
    /// The first two closure arguments are the exact signed global voting
    /// topology and its Proof-of-Possession entries. The third argument lists
    /// signed, non-voting observer identities in stable builder order. Observer
    /// identities may be referenced by observer-specific post-topology metadata,
    /// but cannot sign global or participant-committee work and must not be added
    /// to the signed global voting roster returned by the closure. Use
    /// [`Self::with_genesis_block_and_committee_validator_entries`] when a
    /// participant dataspace needs independently signing validators.
    ///
    /// The same normalization, pre-execution, and voting-roster validation as
    /// [`Self::with_genesis_block`] is applied to the returned block.
    pub fn with_genesis_block_and_observers<F>(mut self, build: F) -> Self
    where
        F: Fn(UniqueVec<PeerId>, Vec<GenesisTopologyEntry>, Vec<PeerId>) -> GenesisBlock
            + Send
            + Sync
            + 'static,
    {
        self.custom_genesis = Some(Arc::new(
            move |topology,
                  topology_entries,
                  _committee_validators,
                  _committee_validator_entries,
                  observers,
                  _observer_entries| { build(topology, topology_entries, observers) },
        ));
        self.genesis_isi = vec![Vec::new()];
        self
    }
    /// Override genesis using proof-bearing supplementary committee validators.
    ///
    /// The first two closure arguments are the exact signed global voting
    /// topology and its PoP entries. The third contains configured Validator
    /// processes and PoPs that remain outside that topology but may be
    /// registered with `RegisterCommitteePeerWithPop` for participant lanes.
    pub fn with_genesis_block_and_committee_validator_entries<F>(mut self, build: F) -> Self
    where
        F: Fn(
                UniqueVec<PeerId>,
                Vec<GenesisTopologyEntry>,
                Vec<GenesisTopologyEntry>,
            ) -> GenesisBlock
            + Send
            + Sync
            + 'static,
    {
        self.custom_genesis = Some(Arc::new(
            move |topology,
                  topology_entries,
                  _committee_validators,
                  committee_validator_entries,
                  _observers,
                  _observer_entries| {
                build(topology, topology_entries, committee_validator_entries)
            },
        ));
        self.genesis_isi = vec![Vec::new()];
        self
    }
    pub fn with_base_seed(mut self, seed: impl ToString) -> Self {
        self.seed = Some(seed.to_string());
        self
    }
    /// Set the base seed only when the builder does not already have one.
    ///
    /// This is useful for harness helpers that want deterministic peer identities by default,
    /// while still allowing callers to override the seed explicitly.
    pub fn with_base_seed_if_unset(mut self, seed: impl ToString) -> Self {
        if self.seed.is_none() {
            self.seed = Some(seed.to_string());
        }
        self
    }
    /// Set [`IvmFuelConfig`].
    ///
    /// The builder defaults to [`IvmFuelConfig::Auto`], ensuring non-optimized IVM builds receive
    /// a higher fuel allowance unless explicitly overridden.
    pub fn with_ivm_fuel(mut self, config: IvmFuelConfig) -> Self {
        self.ivm_fuel = config;
        self
    }
    /// Build the [`Network`]. Doesn't start it.
    pub fn build(self) -> Network {
        let permit = acquire_network_permit();
        self.build_with_permit(permit)
    }
    fn build_with_permit(self, permit: NetworkPermit) -> Network {
        let NetworkBuilder {
            n_peers,
            max_validator_capacity,
            committee_validator_p2p_bootstrap,
            observer_p2p_bootstrap,
            observer_slow_reader_relays,
            mut config_layers,
            block_cadence,
            sync_timeout,
            peer_startup_timeout,
            ivm_fuel,
            mut genesis_isi,
            mut genesis_post_topology_isi,
            custom_genesis,
            seed,
            genesis_key_pair,
            block_sync_gossip_period,
            consensus_mode,
            auto_populate_trusted_peer_pops,
            genesis_committee_keys_for_global_peers,
            npos_genesis_bootstrap_stake,
            private_settlement_route_control,
            parliament_test_signers,
            topology_genesis_isi,
        } = self;
        let chain_discriminant = materialize_profile_account_defaults(&mut config_layers)
            .unwrap_or_else(|error| panic!("invalid test-network profile defaults: {error:#}"));
        // Builder-owned instruction generation and custom genesis callbacks use the
        // selected configuration profile, including when preparation runs on a worker.
        let _profile =
            iroha_data_model::account::address::ChainDiscriminantGuard::enter(chain_discriminant);
        let max_validator_capacity = max_validator_capacity.unwrap_or(n_peers);
        let ingress_validator_capacity = authenticated_validator_capacity(
            max_validator_capacity,
            consensus_mode,
            &genesis_isi,
            &genesis_post_topology_isi,
        )
        .unwrap_or_else(|error| {
            panic!("failed to derive authenticated test-network validator capacity: {error}")
        });
        let observer_count = observer_p2p_bootstrap.map_or(0, |bootstrap| {
            bootstrap
                .validate_for_validators(
                    max_validator_capacity
                        .checked_add(
                            committee_validator_p2p_bootstrap
                                .map_or(0, CommitteeValidatorP2pBootstrap::validator_count),
                        )
                        .expect("validator participant count cannot overflow"),
                    ObserverP2pBootstrap::connection_capacity(),
                )
                .unwrap_or_else(|error| panic!("invalid observer P2P bootstrap: {error}"));
            bootstrap.observer_count()
        });
        let committee_validator_count = committee_validator_p2p_bootstrap.map_or(0, |bootstrap| {
            bootstrap
                .validate_for_network(
                    max_validator_capacity,
                    observer_count,
                    CommitteeValidatorP2pBootstrap::connection_capacity(),
                )
                .unwrap_or_else(|error| {
                    panic!("invalid committee-validator P2P bootstrap: {error}")
                });
            bootstrap.validator_count()
        });
        let participant_count = n_peers
            .checked_add(committee_validator_count)
            .expect("validated committee-validator participant count cannot overflow")
            .checked_add(observer_count)
            .expect("validated P2P participant count cannot overflow");
        // A builder is a reusable network recipe. Allocate the environment only
        // when the recipe is built so retrying a cloned recipe cannot inherit a
        // previous attempt's peer directories, Kura state, logs, or ports.
        let env = Environment::new();
        // Keep Nexus sink/escrow account literals parseable for unregister-guard checks even
        // when callers don't provide explicit nexus account overrides.
        let genesis_account_literal = ALICE_ID
            .to_i105_for_discriminant(chain_discriminant)
            .expect("harness genesis account renders for selected profile");
        let has_fee_sink_override = config_layers.iter().any(|layer| {
            get_nested_value(layer, &["nexus", "fees", "fee_sink_account_id"]).is_some()
        });
        let has_fee_asset_override = config_layers
            .iter()
            .any(|layer| get_nested_value(layer, &["nexus", "fees", "fee_asset_id"]).is_some());
        let has_stake_escrow_override = config_layers.iter().any(|layer| {
            get_nested_value(layer, &["nexus", "staking", "stake_escrow_account_id"]).is_some()
        });
        let has_slash_sink_override = config_layers.iter().any(|layer| {
            get_nested_value(layer, &["nexus", "staking", "slash_sink_account_id"]).is_some()
        });
        if !(has_fee_sink_override && has_stake_escrow_override && has_slash_sink_override) {
            let mut nexus_accounts_layer = Table::new();
            if !has_fee_sink_override {
                TomlWriter::new(&mut nexus_accounts_layer).write(
                    ["nexus", "fees", "fee_sink_account_id"],
                    genesis_account_literal.clone(),
                );
            }
            if !has_stake_escrow_override {
                TomlWriter::new(&mut nexus_accounts_layer).write(
                    ["nexus", "staking", "stake_escrow_account_id"],
                    genesis_account_literal.clone(),
                );
            }
            if !has_slash_sink_override {
                TomlWriter::new(&mut nexus_accounts_layer).write(
                    ["nexus", "staking", "slash_sink_account_id"],
                    genesis_account_literal.clone(),
                );
            }
            config_layers.push(nexus_accounts_layer);
        }
        let parliament_beacon_signer_modes = parliament_test_signers
            .as_ref()
            .map(|selection| selection.resolve(n_peers));
        let validator_program = match (
            private_settlement_route_control,
            parliament_beacon_signer_modes.is_some(),
        ) {
            (false, false) => Program::Irohad,
            (true, false) => Program::IrohadPrivateSettlementRoutes,
            (false, true) => Program::IrohadParliamentSigners,
            (true, true) => unreachable!("builder methods reject combined test daemons"),
        };
        let peers: Vec<_> = (0..n_peers)
            .map(|i| {
                let seed = seed.as_ref().map(|x| format!("{x}-peer-{i}"));
                NetworkPeerBuilder::new()
                    .with_seed(seed.as_ref().map(|x| x.as_bytes()))
                    .with_parliament_beacon_signer_mode(
                        parliament_beacon_signer_modes
                            .as_ref()
                            .map(|modes| modes[i]),
                    )
                    .build_with_program(&env, validator_program)
            })
            .collect();
        let committee_validators: Vec<_> = (0..committee_validator_count)
            .map(|i| {
                let seed = seed
                    .as_ref()
                    .map(|x| format!("{x}-committee-validator-{i}"));
                NetworkPeerBuilder::new()
                    .with_seed(seed.as_ref().map(|x| x.as_bytes()))
                    .build_with_program(&env, validator_program)
            })
            .collect();
        let observers: Vec<_> = (0..observer_count)
            .map(|i| {
                let seed = seed.as_ref().map(|x| format!("{x}-observer-{i}"));
                NetworkPeerBuilder::new()
                    .with_seed(seed.as_ref().map(|x| x.as_bytes()))
                    .build_with_program(
                        &env,
                        if private_settlement_route_control {
                            Program::IrohadPrivateSettlementRoutes
                        } else {
                            Program::Irohad
                        },
                    )
            })
            .collect();
        let observer_slow_reader_relays = observer_slow_reader_relays
            .map(|config| ObserverSlowReaderRelays::new(&observers, config));
        let observer_advertised_p2p_addresses = observer_slow_reader_relays
            .as_ref()
            .map(ObserverSlowReaderRelays::published_addresses)
            .unwrap_or_default();
        let peer_ids: UniqueVec<PeerId> = peers.iter().map(NetworkPeer::id).collect();
        let collected_entries: Vec<GenesisTopologyEntry> =
            peers.iter().filter_map(NetworkPeer::genesis_pop).collect();
        assert_eq!(
            collected_entries.len(),
            peers.len(),
            "every network peer must provide a BLS PoP"
        );
        let topology_entries: Vec<GenesisTopologyEntry> = collected_entries.clone();
        let committee_validator_entries: Vec<GenesisTopologyEntry> = committee_validators
            .iter()
            .filter_map(NetworkPeer::genesis_pop)
            .collect();
        assert_eq!(
            committee_validator_entries.len(),
            committee_validators.len(),
            "every supplementary committee validator must provide a BLS PoP"
        );
        let observer_entries: Vec<GenesisTopologyEntry> = observers
            .iter()
            .filter_map(NetworkPeer::genesis_pop)
            .collect();
        assert_eq!(
            observer_entries.len(),
            observers.len(),
            "every signed observer must provide a BLS PoP"
        );
        let peer_topology: Vec<PeerId> = peer_ids.iter().cloned().collect();
        for build in &topology_genesis_isi {
            assert!(
                custom_genesis.is_none(),
                "custom genesis owns its topology-derived instructions"
            );
            let isi = build(&topology_entries);
            if !isi.is_empty() {
                genesis_post_topology_isi.push(isi);
            }
        }
        if genesis_committee_keys_for_global_peers {
            assert!(
                custom_genesis.is_none(),
                "custom genesis owns its Committee-key registration"
            );
            genesis_post_topology_isi.push(genesis_participant_committee_key_instructions(
                &topology_entries,
                &peer_topology,
            ));
        }
        let mut config_layers_for_parse = Vec::with_capacity(config_layers.len() + 3);
        config_layers_for_parse.push(
            Table::new()
                .write("chain", config::chain_id().to_string())
                .write(
                    ["genesis", "public_key"],
                    genesis_key_pair.public_key().to_string(),
                ),
        );
        config_layers_for_parse.push(trusted_peers_layer_for_parse_with_observer_addresses(
            &peers,
            &committee_validators,
            &observers,
            &observer_advertised_p2p_addresses,
            auto_populate_trusted_peer_pops,
        ));
        config_layers_for_parse.extend(config_layers.iter().cloned());
        let pre_genesis_peer = peers
            .first()
            .expect("revision-4 test network has at least four validators");
        let resolved_pre_genesis_config = resolve_actual_config_result(
            pre_genesis_peer,
            &config_layers_for_parse,
        )
        .unwrap_or_else(|error| {
            panic!(
                "pre-genesis fully merged test-network config for peer `{}` is invalid: {error:#}",
                pre_genesis_peer.mnemonic()
            )
        });
        let observer_ids = observers.iter().map(NetworkPeer::id).collect::<Vec<_>>();
        let committee_validator_ids = committee_validators
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        let custom_genesis_block = custom_genesis.as_ref().map(|builder_fn| {
            builder_fn(
                peer_ids.clone(),
                topology_entries.clone(),
                committee_validator_ids.clone(),
                committee_validator_entries.clone(),
                observer_ids.clone(),
                observer_entries.clone(),
            )
        });
        if let Some(custom) = custom_genesis_block.as_ref() {
            assert_genesis_voting_roster_matches_network(custom, &peer_topology);
        }
        let cached_genesis = OnceLock::new();
        let block_cadence = block_cadence.unwrap_or(DEFAULT_BLOCK_CADENCE);
        let set_ivm_fuel = match ivm_fuel {
            IvmFuelConfig::Unset => None,
            IvmFuelConfig::Value(value) => Some(value),
            IvmFuelConfig::Auto => match iroha_test_samples::load_ivm_build_profile() {
                Some(profile) if profile.is_optimized() => None,
                Some(_) => Some(NON_OPTIMIZED_IVM_FUEL),
                None => Some(NON_OPTIMIZED_IVM_FUEL),
            },
        }
        .map(|value| {
            InstructionBox::from(SetParameter::new(Parameter::SmartContract(
                SmartContractParameter::Fuel(value),
            )))
        });
        let consensus_chain_id = resolved_pre_genesis_config.common.chain.clone();
        let mut parameter_prefix: Vec<InstructionBox> = Vec::new();
        if let Some(fuel) = set_ivm_fuel {
            parameter_prefix.push(fuel);
        }
        let npos_snapshot = npos_params_from_genesis(&genesis_isi, &genesis_post_topology_isi)
            .unwrap_or_else(|error| panic!("{error}"));
        let xor_asset_id = npos_snapshot.as_ref().map_or_else(
            || {
                iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
                    .parse::<AssetDefinitionId>()
                    .expect("canonical fixture XOR asset")
            },
            |parameters| parameters.xor_asset_definition_id.clone(),
        );
        match (consensus_mode, npos_snapshot) {
            (ConsensusMode::Npos, Some(_)) | (ConsensusMode::Permissioned, None) => {}
            (ConsensusMode::Npos, None) => {
                // Materialize one explicit signed snapshot before deriving the
                // consensus carrier. Runtime code never falls back to local
                // configuration or implicit defaults.
                let chain_hash =
                    CryptoHash::new(consensus_chain_id.clone().into_inner().as_bytes());
                let mut npos = SumeragiNposParameters::default();
                npos.epoch_seed = chain_hash.into();
                npos.validate()
                    .expect("test-network NPoS genesis snapshot must be valid");
                parameter_prefix.push(InstructionBox::from(SetParameter::new(Parameter::Custom(
                    npos.into_custom_parameter(),
                ))));
            }
            (ConsensusMode::Permissioned, Some(_)) => {
                panic!("permissioned genesis must omit `sumeragi_npos_parameters`");
            }
        }
        {
            let first_tx = genesis_isi
                .first_mut()
                .expect("at least one genesis transaction exists");
            first_tx.splice(0..0, parameter_prefix);
        }
        let nexus_domain = DomainId::try_new("nexus", "universal").expect("nexus domain");
        let ivm_domain = DomainId::try_new("ivm", "universal").expect("ivm domain");
        let universal_domain =
            DomainId::try_new("universal", "universal").expect("universal domain");
        let stake_asset_id = xor_asset_id.clone();
        let fee_asset_id = xor_asset_id;
        let bootstrap_gas_keypair = checked_key_pair_from_seed(
            b"iroha_test_network::npos_bootstrap_gas_account".to_vec(),
            Algorithm::Ed25519,
        );
        let gas_account_id = AccountId::new(bootstrap_gas_keypair.public_key().clone());
        let generated_validator_accounts = peers
            .iter()
            .map(NetworkPeer::account_id)
            .collect::<BTreeSet<_>>();
        let caller_registered_accounts = genesis_isi
            .iter()
            .chain(&genesis_post_topology_isi)
            .flatten()
            .filter_map(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .and_then(|register| match register {
                        RegisterBox::Account(register) => Some(register.object.id.clone()),
                        _ => None,
                    })
            })
            .collect::<BTreeSet<_>>();
        let has_permissioned_bootstrap_support_collision = genesis_isi
            .iter()
            .chain(&genesis_post_topology_isi)
            .flatten()
            .any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .is_some_and(|register| match register {
                        RegisterBox::Domain(register) => {
                            register.object.id == nexus_domain
                                || register.object.id == ivm_domain
                                || register.object.id == universal_domain
                        }
                        RegisterBox::Account(register) => {
                            register.object.id == gas_account_id
                                || generated_validator_accounts.contains(&register.object.id)
                        }
                        RegisterBox::AssetDefinition(register) => {
                            register.object.id == stake_asset_id
                                || register.object.id == fee_asset_id
                        }
                        _ => false,
                    })
            });
        // Staking is NPoS-only: the network XOR identity that staking and rewards use lives in the
        // signed NPoS parameters, which permissioned genesis omits. A permissioned network
        // therefore registers no public-lane validators; its committee is the genesis roster
        // (`RegisterPeerWithPop`). Both modes provision the genesis XOR fee resources unless the
        // caller owns them.
        let validator_stake = match consensus_mode {
            ConsensusMode::Npos => npos_genesis_bootstrap_stake.map(|stake_amount| {
                resolve_npos_bootstrap_stake(&genesis_isi, &genesis_post_topology_isi, stake_amount)
            }),
            ConsensusMode::Permissioned => None,
        };
        let fee_resource_bootstrap = validator_stake.is_some()
            || (matches!(consensus_mode, ConsensusMode::Permissioned)
                && custom_genesis.is_none()
                && !has_fee_asset_override
                && !has_permissioned_bootstrap_support_collision);
        if fee_resource_bootstrap {
            let gas_account_str = gas_account_id
                .to_i105_for_discriminant(chain_discriminant)
                .expect("harness bootstrap custody renders for selected profile");
            let mut bootstrap_layer = Table::new();
            let mut writer = TomlWriter::new(&mut bootstrap_layer);
            writer.write(["nexus", "fees", "fee_asset_id"], fee_asset_id.to_string());
            if validator_stake.is_some() {
                writer
                    .write(
                        ["nexus", "staking", "stake_asset_id"],
                        stake_asset_id.to_string(),
                    )
                    .write(
                        ["nexus", "staking", "stake_escrow_account_id"],
                        gas_account_str.clone(),
                    )
                    .write(
                        ["nexus", "staking", "slash_sink_account_id"],
                        gas_account_str,
                    );
            }
            config_layers.push(bootstrap_layer);
            // Staking and transaction fees consume the same genesis-selected XOR.
            // These explicit allocations belong only to this isolated fixture network.
            let definition = AssetDefinition::new(
                stake_asset_id.clone(),
                "XOR".to_owned(),
                NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .with_metadata(Metadata::default());
            let fee_seed_amount = 1_000_000_u32;
            let mut bootstrap_tx = vec![
                Register::domain(Domain::new(nexus_domain.clone())).into(),
                Register::domain(Domain::new(ivm_domain.clone())).into(),
                Register::domain(Domain::new(universal_domain)).into(),
                Register::account(Account::new(gas_account_id.clone())).into(),
                Register::asset_definition(definition).into(),
            ];
            for peer in &peers {
                let validator_id = peer.account_id();
                bootstrap_tx.push(Register::account(Account::new(validator_id.clone())).into());
                if let Some(stake_amount) = &validator_stake {
                    bootstrap_tx.push(
                        Mint::asset_quantity(
                            stake_amount.clone(),
                            AssetId::new(stake_asset_id.clone(), validator_id.clone()),
                        )
                        .into(),
                    );
                }
                bootstrap_tx.push(
                    Mint::asset_quantity(
                        fee_seed_amount,
                        AssetId::new(fee_asset_id.clone(), validator_id),
                    )
                    .into(),
                );
            }
            for account_id in [
                ALICE_ID.clone(),
                BOB_ID.clone(),
                CARPENTER_ID.clone(),
                gas_account_id.clone(),
            ] {
                bootstrap_tx.push(
                    Mint::asset_quantity(
                        fee_seed_amount,
                        AssetId::new(fee_asset_id.clone(), account_id),
                    )
                    .into(),
                );
            }
            genesis_post_topology_isi.push(bootstrap_tx);
            if let Some(stake_amount) = validator_stake {
                // Each registration moves one original stake transfer; activation moves none.
                // Keep each generated entry within both signed bootstrap source-count limits.
                // Native pre-execution still admits the complete original source and byte bounds.
                let intrinsic =
                    iroha_data_model::parameter::FastpqSourcePolicyV1::bootstrap().intrinsic;
                let registrations_per_entry =
                    usize::try_from(intrinsic.max_transcripts.min(intrinsic.max_deltas))
                        .expect("bootstrap source count fits usize");
                for group in peers.chunks(registrations_per_entry) {
                    let mut validator_tx = Vec::new();
                    for peer in group {
                        let validator_id = peer.account_id();
                        validator_tx.push(
                    RegisterPublicLaneValidator {
                        lane_id: LaneId::SINGLE,
                        validator: validator_id.clone(),
                        peer_id: peer.id(),
                        stake_account: validator_id.clone(),
                        initial_stake: stake_amount.clone(),
                        metadata: Metadata::default(),
                        monetary_plan:
                            iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                                AssetId::new(stake_asset_id.clone(), validator_id.clone()),
                                AssetId::new(stake_asset_id.clone(), gas_account_id.clone()),
                                stake_amount.clone(),
                            ),
                    }
                    .into(),
                );
                        validator_tx.push(
                            ActivatePublicLaneValidator {
                                lane_id: LaneId::SINGLE,
                                validator: validator_id,
                            }
                            .into(),
                        );
                    }
                    genesis_post_topology_isi.push(validator_tx);
                }
            }
        }
        if custom_genesis.is_none() {
            let agent_wallet_asset_definition =
                AssetDefinitionId::parse_address_literal("61CtjvNd9T3THAR65GsMVHr82Bjc")
                    .expect("soracloud agent wallet asset definition id");
            let hf_shared_lease_asset_definition =
                AssetDefinitionId::parse_address_literal("5PeSrQmLNwwKtruJvDZrbrm9RuMw")
                    .expect("soracloud HF shared lease asset definition id");
            let mut soracloud_validator_bootstrap = Vec::new();
            let mut seeded_accounts = BTreeSet::new();
            let register_validator_accounts = !fee_resource_bootstrap;
            for peer in &peers {
                let account_id = peer.account_id();
                if !seeded_accounts.insert(account_id.clone()) {
                    continue;
                }
                if register_validator_accounts && !caller_registered_accounts.contains(&account_id)
                {
                    soracloud_validator_bootstrap
                        .push(Register::account(Account::new(account_id.clone())).into());
                }
                soracloud_validator_bootstrap.push(
                    Grant::account_permission(
                        Permission::new("CanManageSoracloud".into(), Json::new(())),
                        account_id.clone(),
                    )
                    .into(),
                );
                soracloud_validator_bootstrap.push(
                    Mint::asset_quantity(
                        500_000_u32,
                        AssetId::new(agent_wallet_asset_definition.clone(), account_id.clone()),
                    )
                    .into(),
                );
                soracloud_validator_bootstrap.push(
                    Mint::asset_quantity(
                        500_000_u32,
                        AssetId::new(hf_shared_lease_asset_definition.clone(), account_id),
                    )
                    .into(),
                );
            }
            if !soracloud_validator_bootstrap.is_empty() {
                genesis_post_topology_isi.push(soracloud_validator_bootstrap);
            }
        }
        let gossip_ms = i64::try_from(block_sync_gossip_period.as_millis())
            .expect("block gossip period fits in i64 milliseconds");
        let participant_fanout = i64::try_from(participant_count)
            .expect("bounded observer participant count fits in i64");
        let mut base_layer =
            config::base_iroha_config().write("chain", consensus_chain_id.to_string());
        base_layer = base_layer
            .write(["network", "block_gossip_period_ms"], gossip_ms)
            // Fan-out gossip to all peers so block sync converges quickly in multi-peer
            // integration scenarios (NPoS liveness and certified-body recovery).
            .write(["network", "block_gossip_size"], participant_fanout);
        base_layer = base_layer.write(
            ["genesis", "public_key"],
            genesis_key_pair.public_key().to_string(),
        );
        base_layer = base_layer
            // Ensure BLS batching stays enabled so PoP-based peers can register and vote.
            .write(["pipeline", "signature_batch_max_bls"], 4i64)
            // Enable Norito-RPC for test networks so client-based flows keep working out of the box.
            .write(["torii", "transport", "norito_rpc", "stage"], "ga")
            .write(["torii", "transport", "norito_rpc", "enabled"], true);
        // Resolve the same ordered layers that peers will consume. The provisional
        // genesis commitment must include the exact runtime pipeline and Nexus
        // projection, including config layers injected for validator bootstrap.
        let mut final_config_layers_for_parse = Vec::with_capacity(config_layers.len() + 2);
        final_config_layers_for_parse.push(trusted_peers_layer_for_parse_with_observer_addresses(
            &peers,
            &committee_validators,
            &observers,
            &observer_advertised_p2p_addresses,
            auto_populate_trusted_peer_pops,
        ));
        final_config_layers_for_parse.push(base_layer.clone());
        final_config_layers_for_parse.extend(config_layers.iter().cloned());
        let resolved_genesis_config = Some(resolve_final_actual_config(
            peers
                .first()
                .expect("revision-4 test network has at least four validators"),
            &final_config_layers_for_parse,
        ));
        validate_planned_validator_capacity(
            resolved_genesis_config
                .as_ref()
                .expect("final test-network config was just resolved"),
            ingress_validator_capacity,
        )
        .unwrap_or_else(|error| {
            panic!(
                "final fully merged test-network config does not reserve the authenticated/planned maximum validator capacity: {error:#}"
            )
        });
        if let Some(bootstrap) = observer_p2p_bootstrap {
            let configured_capacity = resolved_genesis_config
                .as_ref()
                .map(|config| effective_network_reply_source_capacity(&config.network))
                .unwrap_or_else(ObserverP2pBootstrap::connection_capacity)
                .min(ObserverP2pBootstrap::connection_capacity());
            bootstrap
                .validate_for_validators(
                    max_validator_capacity
                        .checked_add(committee_validator_count)
                        .expect("validator participant count cannot overflow"),
                    configured_capacity,
                )
                .unwrap_or_else(|error| {
                    panic!("observer P2P fanout exceeds effective network capacity: {error}")
                });
        }
        if let Some(bootstrap) = committee_validator_p2p_bootstrap {
            let configured_capacity = resolved_genesis_config
                .as_ref()
                .map(|config| effective_network_reply_source_capacity(&config.network))
                .unwrap_or_else(CommitteeValidatorP2pBootstrap::connection_capacity)
                .min(CommitteeValidatorP2pBootstrap::connection_capacity());
            bootstrap
                .validate_for_network(max_validator_capacity, observer_count, configured_capacity)
                .unwrap_or_else(|error| {
                    panic!(
                        "committee-validator P2P fanout exceeds effective network capacity: {error}"
                    )
                });
        }
        // Build consensus parameters from the effective genesis instructions (base + post-topology),
        // so consensus metadata is consistent with the final submitted genesis layout.
        let da_proof_policies = resolved_genesis_config
            .as_ref()
            .map(|config| iroha_core::da::proof_policy_bundle(&config.nexus.lane_config));
        let confidential_policy_hash = Some(resolved_genesis_config.as_ref().map_or_else(
            iroha_core::state::default_genesis_confidential_policy_hash,
            |config| iroha_core::state::compute_genesis_confidential_policy_hash(&config.zk),
        ));
        let genesis_crypto = resolved_genesis_config
            .as_ref()
            .map(|config| config::manifest_crypto_from_actual(&config.crypto));
        let pipeline_config = resolved_genesis_config
            .as_ref()
            .map(|config| config.pipeline.clone());
        let nexus_config = resolved_genesis_config
            .as_ref()
            .map(|config| config.nexus.clone());
        let zk_config = resolved_genesis_config
            .as_ref()
            .map(|config| config.zk.clone());
        let (mut parameter_state, preview_staged_policy_hashes) =
            match custom_genesis_block.as_ref() {
                Some(custom) => (
                    consensus_parameters_from_genesis_with_overrides(
                        custom,
                        &genesis_isi,
                        &genesis_post_topology_isi,
                    ),
                    None,
                ),
                None => {
                    let (preview_genesis, staged_hash, _) =
                    config::genesis_with_keypair_and_post_topology_with_policies_and_staged_hash(
                        genesis_isi.clone(),
                        genesis_post_topology_isi.clone(),
                        peer_ids.clone(),
                        topology_entries.clone(),
                        genesis_key_pair.clone(),
                        consensus_chain_id.clone(),
                        genesis_crypto.clone(),
                        da_proof_policies.clone(),
                        pipeline_config.clone(),
                        nexus_config.clone(),
                        zk_config.clone(),
                        resolved_genesis_config.clone(),
                        None,
                        Some(match consensus_mode {
                            ConsensusMode::Permissioned => SumeragiConsensusMode::Permissioned,
                            ConsensusMode::Npos => SumeragiConsensusMode::Npos,
                        }),
                        confidential_policy_hash,
                    );
                    assert_genesis_voting_roster_matches_network(&preview_genesis, &peer_topology);
                    (
                        consensus_parameters_from_genesis(&preview_genesis),
                        Some(staged_hash),
                    )
                }
            };
        parameter_state.sumeragi.block_cadence_ms = std::num::NonZeroU64::new(
            u64::try_from(block_cadence.as_millis())
                .expect("signed block cadence fits into u64 milliseconds"),
        )
        .expect("signed block cadence must be non-zero");
        let mut consensus_mode_tag = PERMISSIONED_TAG;
        let mut consensus_bls_domain = PERMISSIONED_BLS_DOMAIN;
        if matches!(consensus_mode, ConsensusMode::Npos) {
            consensus_mode_tag = NPOS_TAG;
            consensus_bls_domain = NPOS_BLS_DOMAIN;
        }
        let provisional_metadata = parameter_state
            .custom()
            .get(&consensus_metadata::handshake_meta_id())
            .and_then(|parameter| {
                norito::json::from_str::<ConsensusHandshakeMetadata>(parameter.payload().get()).ok()
            })
            .expect(
                "test-network genesis must carry explicitly provisioned signed Sumeragi context parameters",
            );
        let provisional_sumeragi_context = provisional_metadata.sumeragi_context;
        let provisional_params =
            iroha_core::sumeragi::consensus::consensus_genesis_params_from_parameters(
                consensus_mode,
                &parameter_state,
                provisional_sumeragi_context.clone(),
            )
            .expect("test-network genesis parameters must form a canonical carrier");
        let provisional_profile = ConsensusBootstrapProfile {
            params: provisional_params,
            mode_tag: consensus_mode_tag,
            bls_domain: consensus_bls_domain,
            chain_id: consensus_chain_id.clone(),
            wire_protocol_version: PROTO_VERSION,
        };
        let staged_policy_hashes = match custom_genesis_block.as_ref() {
            Some(custom) => {
                let provisional = normalize_genesis_parameters(
                    custom,
                    &genesis_isi,
                    &genesis_post_topology_isi,
                    &consensus_handshake_parameter(&provisional_profile),
                    &genesis_key_pair,
                    da_proof_policies.as_ref(),
                    confidential_policy_hash,
                );
                config::discover_generated_policy_hashes(config::staged_genesis_policy_hashes(
                    &provisional,
                    &AccountId::new(genesis_key_pair.public_key().clone()),
                    &peer_topology,
                    &genesis_key_pair,
                    pipeline_config.as_ref(),
                    nexus_config.as_ref(),
                    zk_config.as_ref(),
                    resolved_genesis_config.as_ref(),
                ))
                .expect("normalized custom genesis must derive its staged Sumeragi context")
            }
            None => preview_staged_policy_hashes
                .expect("normal genesis preview must provide staged execution-policy hashes"),
        };
        let mut signed_sumeragi_context = provisional_sumeragi_context;
        signed_sumeragi_context.nexus_amx_context_hash = staged_policy_hashes.nexus_amx.into();
        signed_sumeragi_context.execution_policy_hash =
            staged_policy_hashes.execution_policy.into();
        let consensus_params =
            iroha_core::sumeragi::consensus::consensus_genesis_params_from_parameters(
                consensus_mode,
                &parameter_state,
                signed_sumeragi_context,
            )
            .expect("bound test-network genesis parameters must form a canonical carrier");
        let consensus_profile = ConsensusBootstrapProfile {
            params: consensus_params,
            mode_tag: consensus_mode_tag,
            bls_domain: consensus_bls_domain,
            chain_id: consensus_chain_id.clone(),
            wire_protocol_version: PROTO_VERSION,
        };
        debug!(
            profile_block_cadence_ms = consensus_profile.params.block_cadence_ms.get(),
            profile_block_max_transactions = consensus_profile.params.block_max_transactions.get(),
            profile_fingerprint = %format!("0x{}", hex_lower(&consensus_profile.fingerprint())),
            "resolved consensus profile for genesis"
        );
        let replaced_in_genesis = replace_consensus_handshake_meta(&mut genesis_isi);
        let replaced_in_post_topology =
            replace_consensus_handshake_meta(&mut genesis_post_topology_isi);
        let consensus_handshake_meta = consensus_handshake_parameter(&consensus_profile);
        if replaced_in_genesis || replaced_in_post_topology {
            debug!(
                replaced = replaced_in_genesis || replaced_in_post_topology,
                "replaced existing consensus_handshake_meta in genesis with computed profile"
            );
        }
        if !(genesis_instructions_contain_consensus_handshake_meta(
            &genesis_isi,
            &consensus_handshake_meta,
        ) || genesis_instructions_contain_consensus_handshake_meta(
            &genesis_post_topology_isi,
            &consensus_handshake_meta,
        )) {
            let instruction =
                InstructionBox::from(SetParameter::new(consensus_handshake_meta.clone()));
            if genesis_isi.is_empty() {
                genesis_isi.push(vec![instruction]);
            } else {
                genesis_isi[0].push(instruction);
            }
            debug!(
                inserted = true,
                "inserted computed consensus_handshake_meta into genesis instructions"
            );
        }
        if let Some(custom) = custom_genesis_block.as_ref() {
            let mut final_custom = normalize_genesis_parameters(
                custom,
                &genesis_isi,
                &genesis_post_topology_isi,
                &consensus_handshake_meta,
                &genesis_key_pair,
                da_proof_policies.as_ref(),
                confidential_policy_hash,
            );
            let (signed_block, final_staged_hash) = config::preexecute_genesis_with_runtime_config(
                &final_custom,
                &AccountId::new(genesis_key_pair.public_key().clone()),
                &peer_topology,
                &genesis_key_pair,
                pipeline_config.as_ref(),
                nexus_config.as_ref(),
                zk_config.as_ref(),
                resolved_genesis_config.as_ref(),
            )
            .expect("final custom genesis must pre-execute without synthetic results");
            assert_eq!(
                final_staged_hash, staged_policy_hashes,
                "custom genesis policy binding must be a pre-execution fixed point"
            );
            final_custom.0 = signed_block;
            assert!(
                genesis_has_exactly_one_consensus_handshake(
                    &final_custom,
                    &consensus_handshake_meta
                ),
                "final custom genesis must contain exactly one canonical handshake carrier"
            );
            cached_genesis
                .set(final_custom)
                .expect("final custom genesis should be cached exactly once");
        }
        let mut network = Network {
            env,
            peers,
            committee_validators,
            observers,
            observer_advertised_p2p_addresses,
            observer_slow_reader_relays,
            next_peer_index: AtomicUsize::new(0),
            block_cadence,
            block_sync_gossip_period,
            sync_timeout_override: sync_timeout,
            peer_startup_timeout_override: peer_startup_timeout,
            consensus_profile,
            genesis_key_pair,
            genesis_isi,
            genesis_post_topology_isi,
            cached_genesis,
            generated_genesis_manifest: OnceLock::new(),
            validated_genesis: resolved_genesis_config.as_ref().and_then(|config| {
                (config.nexus.registry.manifest_directory.is_none()
                    && config.nexus.registry.cache_directory.is_none()
                    && !config.nexus.compliance.enabled)
                    .then(OnceLock::new)
            }),
            config_layers: Some(base_layer).into_iter().chain(config_layers).collect(),
            topology_entries,
            auto_populate_trusted_peer_pops,
            max_validator_capacity,
            _permit: permit,
        };
        let exact_genesis_hash = network.genesis().0.hash();
        let network_id = NetworkId::from_genesis_hash(exact_genesis_hash);
        let client_config = PeerClientConfig {
            chain: network.chain_id(),
            network_id,
            chain_discriminant,
            policy: PeerClientPolicy::from_env(),
        };
        for peer in network.all_peers() {
            peer.client_config
                .set(client_config.clone())
                .expect("test-network peer client identity must be initialized exactly once");
        }
        // The test-network generator is the operator provisioning both the
        // signed in-memory genesis and its independent runtime trust anchor.
        // Insert this generated layer before caller layers so deliberate
        // wrong-hash configurations remain observable by negative tests.
        let expected_hash_layer = Table::new().write(
            ["genesis", "expected_hash"],
            genesis_expected_hash_config_literal(&exact_genesis_hash.to_string()),
        );
        debug_assert!(
            !network.config_layers.is_empty(),
            "test network must retain its generated base config layer"
        );
        network.config_layers.insert(1, expected_hash_layer);
        let final_config_layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        for peer in network.validators() {
            let _ = resolve_final_actual_config(peer, &final_config_layers);
        }
        for peer in network.committee_validators() {
            let _ = resolve_final_actual_config(peer, &final_config_layers);
        }
        for peer in network.observers() {
            let mut observer_config_layers = final_config_layers.clone();
            observer_config_layers.push(network.observer_start_layer(peer));
            let _ = resolve_final_actual_config(peer, &observer_config_layers);
        }
        network
    }
    /// Same as [`Self::build`], but also creates a [`Runtime`].
    ///
    /// This method exists for convenience in non-async tests.
    pub fn build_blocking(self) -> (Network, Runtime) {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let network = self.build();
        (network, rt)
    }
    /// Build and start the network.
    ///
    /// Resolves when all peers are running and have committed genesis block.
    /// See [`Network::start_all`].
    pub async fn start(self) -> Result<Network> {
        let network = self.build();
        network.start_all().await?;
        Ok(network)
    }
    /// Combination of [`Self::build_blocking`] and [`Self::start`].
    pub fn start_blocking(self) -> Result<(Network, Runtime)> {
        let (network, rt) = self.build_blocking();
        rt.block_on(async { network.start_all().await })?;
        Ok((network, rt))
    }
}
/// A common signatory in the test network.
///
/// # Example
///
/// ```
/// use iroha_test_network::Signatory;
///
/// let _alice_kp = Signatory::Alice.key_pair();
/// ```
pub enum Signatory {
    Peer,
    Genesis,
    Alice,
}
impl Signatory {
    /// Get the associated key pair
    pub fn key_pair(&self) -> &KeyPair {
        match self {
            Signatory::Peer => &PEER_KEYPAIR,
            Signatory::Genesis => &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
            Signatory::Alice => &ALICE_KEYPAIR,
        }
        .deref()
    }
}
/// Running Iroha peer.
///
/// Aborts peer forcefully when dropped
#[derive(Debug)]
struct PeerRun {
    tasks: JoinSet<()>,
    shutdown: oneshot::Sender<()>,
    fatal_tx: watch::Sender<bool>,
    pid: Option<u32>,
    #[cfg(unix)]
    broker_child: Option<Child>,
}
/// Lifecycle events of a peer
#[derive(Copy, Clone, Debug)]
pub enum PeerLifecycleEvent {
    /// Process spawned
    Spawned,
    /// Server started to respond
    ServerStarted,
    /// Process terminated
    Terminated { status: ExitStatus },
    /// Process was killed
    Killed,
    /// Caught a related pipeline event
    BlockApplied { height: u64 },
}
#[derive(Debug, Clone)]
struct PeerStartContext {
    run_num: usize,
    config_path: PathBuf,
    genesis_path: Option<PathBuf>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    kura_store_dir_key: String,
    kura_store_dir: PathBuf,
    kura_store_dir_value: String,
}
fn parameter_origin_to_string(origin: &ParameterOrigin) -> String {
    match origin {
        ParameterOrigin::File { id, path } => format!("{id} from file `{}`", path.display()),
        ParameterOrigin::Env { id, var } => format!("{id} from env `{var}`"),
        ParameterOrigin::Default { id } => format!("{id} (default)"),
        ParameterOrigin::Custom { message } => format!("custom: {message}"),
    }
}
impl PeerStartContext {
    fn summary(&self) -> String {
        format!(
            "run={}; config_path={}; genesis_path={}; stdout_path={}; stderr_path={}; kura_store_dir_key={}; kura_store_dir_value={}; kura_store_dir={}",
            self.run_num,
            self.config_path.display(),
            self.genesis_path
                .as_ref()
                .map_or_else(|| "<none>".to_string(), |path| path.display().to_string()),
            self.stdout_path.display(),
            self.stderr_path.display(),
            self.kura_store_dir_key,
            self.kura_store_dir_value,
            self.kura_store_dir.display(),
        )
    }
}
#[cfg(test)]
async fn wait_for_start_event(
    mut rx: broadcast::Receiver<PeerLifecycleEvent>,
) -> Option<PeerLifecycleEvent> {
    loop {
        match rx.recv().await {
            Ok(event @ PeerLifecycleEvent::ServerStarted)
            | Ok(event @ PeerLifecycleEvent::Terminated { .. })
            | Ok(event @ PeerLifecycleEvent::Killed) => return Some(event),
            Ok(_) => continue,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return None,
        }
    }
}
const START_CHECKED_FALLBACK_POLL_INTERVAL: Duration = Duration::from_millis(250);
const START_CHECKED_STORAGE_FALLBACK_GRACE: Duration = Duration::from_secs(30);
fn start_checked_storage_fallback_ready(
    has_genesis: bool,
    elapsed: Duration,
    is_running: bool,
    has_block_1: bool,
) -> bool {
    has_genesis && elapsed >= START_CHECKED_STORAGE_FALLBACK_GRACE && is_running && has_block_1
}
/// Network identity and request policy captured when a peer joins its network.
/// Every client for the peer uses this immutable configuration.
#[derive(Clone, Debug)]
struct PeerClientConfig {
    chain: ChainId,
    network_id: NetworkId,
    chain_discriminant: u16,
    policy: PeerClientPolicy,
}

/// Immutable request and transaction deadlines for one attached peer.
#[derive(Clone, Debug)]
struct PeerClientPolicy {
    status_timeout: Duration,
    request_timeout: Duration,
    ttl: Duration,
}
impl PeerClientPolicy {
    fn from_env() -> Self {
        let status_timeout = client_status_timeout_env();
        Self {
            status_timeout,
            request_timeout: client_request_timeout_env(),
            ttl: client_ttl_env(status_timeout),
        }
    }
}

/// Controls execution of an `iroha3d` child process.
///
/// While exists, allocates socket ports and a temporary directory (not cleared automatically).
///
/// It can be started and shut down repeatedly.
/// It stores configuration and logs for each run separately.
///
/// When dropped, aborts the child process (if it is running).
#[derive(Clone, Debug)]
pub struct NetworkPeer {
    mnemonic: String,
    span: tracing::Span,
    key_pair: KeyPair,
    client_config: Arc<OnceLock<PeerClientConfig>>,
    retained_client: Arc<OnceLock<Client>>,
    streaming_key_pair: KeyPair,
    soranet_transport_key_pair: KeyPair,
    bls_key_pair: Option<KeyPair>,
    bls_pop: Option<Vec<u8>>,
    dir: PathBuf,
    run: Arc<Mutex<Option<PeerRun>>>,
    runs_count: Arc<AtomicUsize>,
    is_running: Arc<AtomicBool>,
    events: broadcast::Sender<PeerLifecycleEvent>,
    block_height: watch::Sender<Option<BlockHeight>>,
    stderr_live: Arc<StdMutex<LiveStderrState>>,
    startup_probe: Arc<StdMutex<PeerStartupProbe>>,
    start_context: Arc<StdMutex<Option<PeerStartContext>>>,
    program: Program,
    parliament_beacon_signer_mode: Option<ParliamentBeaconSignerMode>,
    private_settlement_route_control: Option<Arc<PrivateSettlementRouteControl>>,
    #[cfg(unix)]
    disposable_runtime_provider_broker:
        Arc<StdMutex<Option<Arc<disposable_runtime_provider_broker::DisposableBrokerConfig>>>>,
    // dropping these the last
    port_p2p: Arc<AllocatedPort>,
    port_api: Arc<AllocatedPort>,
}
impl NetworkPeer {
    fn should_run_bind_preflight(&self) -> bool {
        should_run_bind_preflight_for_runs_started(self.runs_count.load(Ordering::Relaxed))
    }
    fn record_probe_status(
        probe: &Arc<StdMutex<PeerStartupProbe>>,
        status: &Status,
    ) -> Option<PeerStatusSnapshot> {
        let snapshot = PeerStatusSnapshot::from(status);
        let mut probe = probe.lock().expect("startup probe should not be poisoned");
        probe.last_status = Some(snapshot.clone());
        probe.last_status_error = None;
        probe.last_status_unix_ms = Some(unix_timestamp_ms_now());
        Some(snapshot)
    }
    fn record_probe_error(probe: &Arc<StdMutex<PeerStartupProbe>>, error: &Report) {
        let mut probe = probe.lock().expect("startup probe should not be poisoned");
        probe.last_status_error = Some(snapshot_snippet(&format!("{error:?}")));
        probe.last_status_unix_ms = Some(unix_timestamp_ms_now());
    }
    fn record_probe_sumeragi_status(
        probe: &Arc<StdMutex<PeerStartupProbe>>,
        status: &SumeragiStatus,
    ) -> PeerSumeragiSnapshot {
        let snapshot = PeerSumeragiSnapshot::from(status);
        let mut probe = probe.lock().expect("startup probe should not be poisoned");
        probe.last_sumeragi = Some(snapshot.clone());
        probe.last_sumeragi_error = None;
        probe.last_sumeragi_unix_ms = Some(unix_timestamp_ms_now());
        snapshot
    }
    fn record_probe_sumeragi_error(probe: &Arc<StdMutex<PeerStartupProbe>>, error: &str) {
        let mut probe = probe.lock().expect("startup probe should not be poisoned");
        probe.last_sumeragi_error = Some(snapshot_snippet(error));
        probe.last_sumeragi_unix_ms = Some(unix_timestamp_ms_now());
    }
    fn last_status_peers(probe: &Arc<StdMutex<PeerStartupProbe>>) -> Option<u64> {
        probe
            .lock()
            .ok()
            .and_then(|probe| probe.last_status.as_ref().map(|snapshot| snapshot.peers))
    }
    fn startup_context_summary(&self) -> Option<String> {
        self.start_context
            .lock()
            .ok()
            .and_then(|context| context.as_ref().map(PeerStartContext::summary))
    }
    pub fn builder() -> NetworkPeerBuilder {
        NetworkPeerBuilder::new()
    }
    /// Return this peer's feature-isolated consensus controller, when requested by the builder.
    pub fn private_settlement_route_control(&self) -> Option<&PrivateSettlementRouteControl> {
        self.private_settlement_route_control.as_deref()
    }

    fn append_parliament_beacon_signer_mode_arg(&self, command: &mut tokio::process::Command) {
        if let Some(mode) = self.parliament_beacon_signer_mode {
            debug_assert_eq!(self.program, Program::IrohadParliamentSigners);
            command
                .arg(PARLIAMENT_BEACON_SIGNER_MODE_ARG)
                .arg(mode.child_arg());
        }
    }
    /// Spawn the child process.
    ///
    /// Passed configuration must contain network topology in the `trusted_peers` parameter.
    ///
    /// This function waits for peer server to start working,
    /// in particular it waits for `/status` response and connects to event stream.
    /// However it doesn't wait for genesis block to be committed.
    /// See [`Self::events`]/[`Self::once`]/[`Self::once_block`] to monitor peer's lifecycle.
    ///
    /// # Panics
    /// If peer was not started.
    pub async fn start<T: AsRef<Table>>(
        &self,
        config_layers: impl Iterator<Item = T>,
        genesis: Option<&GenesisBlock>,
    ) -> Result<()> {
        let genesis = PreparedPeerGenesis::prepare_optional(genesis).await?;
        self.start_prepared(config_layers, genesis.as_ref()).await
    }

    async fn start_prepared<T: AsRef<Table>>(
        &self,
        config_layers: impl Iterator<Item = T>,
        genesis: Option<&PreparedPeerGenesis>,
    ) -> Result<()> {
        let storage_layers: Vec<Table> =
            config_layers.map(|layer| layer.as_ref().clone()).collect();
        if self.should_run_bind_preflight() {
            let preflight = preflight_bind_addresses([self.p2p_address(), self.api_address()]);
            if let Err(err) = preflight {
                return Err(err).wrap_err("preflight bind failed for peer");
            }
        }
        let mut run_guard = self.run.lock().await;
        assert!(run_guard.is_none(), "already running");
        let run_num = self.runs_count.fetch_add(1, Ordering::Relaxed) + 1;
        let span = info_span!(parent: &self.span, "peer_run", run_num);
        let has_genesis = genesis.is_some();
        span.in_scope(|| info!(has_genesis, "Starting"));
        let (storage_dir, storage_dir_key, storage_dir_value) =
            resolve_kura_store_dir(self, &storage_layers)?;
        let reset_for_bootstrap =
            Self::should_reset_kura_for_bootstrap(has_genesis, run_num as usize);
        self.prepare_kura_storage_dir(&storage_dir, reset_for_bootstrap)?;
        let existing_genesis_path = self.restart_genesis_file(has_genesis);
        {
            let mut live = self
                .stderr_live
                .lock()
                .expect("stderr live buffer should not be poisoned");
            live.reset(run_num);
        }
        {
            let mut probe = self
                .startup_probe
                .lock()
                .expect("startup probe should not be poisoned");
            *probe = PeerStartupProbe::default();
        }
        let config_layers: Vec<Table> = storage_layers;
        let config_path = self
            .write_run_config(
                config_layers.iter().map(Cow::Borrowed),
                genesis,
                existing_genesis_path.as_deref(),
                run_num,
            )
            .await?;
        let genesis_path = if has_genesis {
            Some(self.dir.join(format!("run-{run_num}-genesis.nrt")))
        } else {
            existing_genesis_path
        };
        let stdout_path = self.dir.join(format!("run-{run_num}-stdout.log"));
        let stderr_path = self.dir.join(format!("run-{run_num}-stderr.log"));
        {
            let mut startup_context = self
                .start_context
                .lock()
                .expect("startup context lock should not be poisoned");
            *startup_context = Some(PeerStartContext {
                run_num,
                config_path: config_path.clone(),
                genesis_path: genesis_path.clone(),
                stdout_path: stdout_path.clone(),
                stderr_path: stderr_path.clone(),
                kura_store_dir_key: storage_dir_key,
                kura_store_dir: storage_dir.clone(),
                kura_store_dir_value: storage_dir_value,
            });
        }
        let use_sora_profile = config_requires_sora_profile(&config_layers);
        let irohad = self.program.resolve_async().await?;
        let irohad =
            revalidate_release_prebuilt_binary(self.program.release_prebuilt_binary(), &irohad)?
                .unwrap_or(irohad);
        #[cfg(unix)]
        let broker_child = self
            .spawn_disposable_runtime_provider_broker(run_num)
            .await?;
        // Only this peer owner's original launch may assert that its fixture-generated key
        // never signed. Missing records on a restart are recovery evidence, not fresh custody.
        let first_consensus_boot = if run_num == 1 {
            let configured = resolve_actual_config_result(self, &config_layers)?;
            let resolve = |path: PathBuf| {
                if path.is_absolute() {
                    path
                } else {
                    self.dir.join(path)
                }
            };
            first_consensus_boot(
                run_num,
                &resolve(configured.sumeragi.records_dir),
                &resolve(configured.sumeragi.installation_log),
            )?
        } else {
            false
        };
        let make_irohad_command = |binary: &Path| {
            let mut cmd = tokio::process::Command::new(binary);
            strip_config_env_overrides(&mut cmd);
            cmd.stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .arg("--config")
                .arg(&config_path)
                .arg("--terminal-colors=true");
            if first_consensus_boot {
                cmd.arg("--sumeragi-assert-fresh-key");
            }
            cmd.env("KURA_STORE_DIR", storage_dir.as_os_str());
            cmd.env_remove(private_settlement_route_control::CONTROL_DIR_ENV);
            if let Some(control) = &self.private_settlement_route_control {
                cmd.env(
                    private_settlement_route_control::CONTROL_DIR_ENV,
                    control.root(),
                );
            }
            if use_sora_profile {
                cmd.arg("--sora");
            }
            self.append_parliament_beacon_signer_mode_arg(&mut cmd);
            if std::env::var_os("IROHA_SKIP_BIND_CHECKS").is_none() {
                cmd.env("IROHA_SKIP_BIND_CHECKS", "1");
            }
            cmd.current_dir(&self.dir);
            Ok::<_, Report>(cmd)
        };
        let mut child = match make_irohad_command(&irohad)?.spawn() {
            Ok(child) => child,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                warn!(
                    binary = %irohad.display(),
                    "cached `iroha3d` path vanished before spawn; rebuilding and retrying once"
                );
                let program = self.program;
                let refreshed = spawn_blocking(move || program.resolve_force_build())
                    .await
                    .wrap_err("failed to join blocking task while refreshing `iroha3d` path")??;
                let refreshed = revalidate_release_prebuilt_binary(
                    program.release_prebuilt_binary(),
                    &refreshed,
                )?
                .unwrap_or(refreshed);
                make_irohad_command(&refreshed)?.spawn().wrap_err_with(|| {
                    eyre!(
                        "failed to spawn `iroha3d` after refreshing binary path: {}",
                        refreshed.display()
                    )
                })?
            }
            Err(err) => return Err(err).wrap_err("failed to spawn `iroha3d`"),
        };
        let pid = child.id();
        let stderr_log_ready = Arc::new(Notify::new());
        let (fatal_tx, fatal_rx) = watch::channel(false);
        self.is_running.store(true, Ordering::Relaxed);
        let _ = self.events.send(PeerLifecycleEvent::Spawned);
        let mut tasks = JoinSet::<()>::new();
        {
            let tasks = &mut tasks;
            let fatal_rx = fatal_rx.clone();
            let is_running = self.is_running.clone();
            let output = child
                .stdout
                .take()
                .ok_or_else(|| eyre!("failed to capture child stdout"))?;
            let file = File::create(&stdout_path)
                .await
                .wrap_err("failed to create stdout log file")?;
            tasks.spawn(async move {
                drain_log_lines(output, file, fatal_rx, is_running, |_| {}, None, "stdout").await;
                // stdout logs are best-effort; no synchronization needed.
            });
        }
        {
            let tasks = &mut tasks;
            let span = span.clone();
            let fatal_rx = fatal_rx.clone();
            let is_running = self.is_running.clone();
            let output = child
                .stderr
                .take()
                .ok_or_else(|| eyre!("failed to capture child stderr"))?;
            let log_path = stderr_path.clone();
            let stderr_log_ready = Arc::clone(&stderr_log_ready);
            let stderr_live = Arc::clone(&self.stderr_live);
            tasks.spawn(async move {
                let buffer = PeerStderrBuffer::new(span, log_path.clone(), stderr_live);
                let file = match File::create(&log_path).await {
                    Ok(file) => file,
                    Err(err) => {
                        error!(?err, ?log_path, "failed to create stderr log file");
                        stderr_log_ready.notify_waiters();
                        return;
                    }
                };
                drain_log_lines(
                    output,
                    file,
                    fatal_rx,
                    is_running,
                    |line| buffer.push_line(line),
                    Some(stderr_log_ready),
                    "stderr",
                )
                .await;
            });
        }
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let is_normal_shutdown_started = Arc::new(AtomicBool::new(false));
        let peer_exit = PeerExit {
            child,
            span: span.clone(),
            is_running: self.is_running.clone(),
            is_normal_shutdown_started: is_normal_shutdown_started.clone(),
            events: self.events.clone(),
            block_height: self.block_height.clone(),
            fatal_rx: fatal_rx.clone(),
            stderr_log_ready,
            stderr_live: self.stderr_live.clone(),
        };
        {
            let tasks = &mut tasks;
            tasks.spawn(
                async move {
                    if let Err(err) = peer_exit.monitor(shutdown_rx).await {
                        error!("something went very bad during peer exit monitoring: {err}");
                    }
                }
                .instrument(span.clone()),
            );
        }
        {
            let tasks = &mut tasks;
            let client = self.retained_client().client().clone();
            let events_tx = self.events.clone();
            let block_height_tx = self.block_height.clone();
            let is_running = self.is_running.clone();
            let fatal_tx = fatal_tx.clone();
            let mut fatal_rx = fatal_rx.clone();
            let torii_addr = self.api_address().to_literal();
            let startup_probe = Arc::clone(&self.startup_probe);
            let startup_warn_gate = StartupWarnGate::new(STARTUP_STATUS_WARN_GRACE);
            tasks.spawn(
                async move {
                    let status_timeout = client.transaction_status_timeout();
                    let status_client = client.clone();
                    let storage_min_height = Arc::new(AtomicU64::new(0));
                    let mut last_progress: Instant;
                    let http_deadline = (status_timeout != Duration::ZERO)
                        .then(|| Instant::now() + status_timeout);
                    let mut http_gate = HttpStartGate::default();
                    let http_seen = Arc::new(AtomicBool::new(false));
                    if STARTUP_STATUS_WARN_GRACE > Duration::ZERO {
                        tokio::select! {
                            _ = tokio::time::sleep(STARTUP_STATUS_WARN_GRACE) => {}
                            changed = fatal_rx.changed() => {
                                if changed.is_ok() && *fatal_rx.borrow() {
                                    debug!("fatal notify received during startup grace");
                                }
                                return;
                            }
                        }
                    }
                    if *fatal_rx.borrow() {
                        return;
                    }
                    let warn_gate = startup_warn_gate.clone();
                    // Retry status reads with exponential backoff (50ms ..= 1s); abort if it takes
                    // longer than the configured timeout. If Torii is slow to accept connections,
                    // fall back to on-disk height observation so peers can still make progress.
                    let status_backoff = {
                        let storage_dir = storage_dir.clone();
                        let storage_min_height = Arc::clone(&storage_min_height);
                        let startup_probe = Arc::clone(&startup_probe);
                        let warn_gate = warn_gate.clone();
                        let http_seen = Arc::clone(&http_seen);
                        move || {
                            let client = status_client.clone();
                            let storage_dir = storage_dir.clone();
                            let min_height = storage_min_height.load(Ordering::Relaxed);
                            let startup_probe = Arc::clone(&startup_probe);
                            let warn_gate = warn_gate.clone();
                            let http_seen = Arc::clone(&http_seen);
                            async move {
                                let status = client.status().get().await.map_err(Report::from);
                                match status {
                                    Ok(status) => {
                                        let _ =
                                            NetworkPeer::record_probe_status(&startup_probe, &status);
                                        Ok((status, StatusSource::Http))
                                    }
                                    Err(err) => {
                                        NetworkPeer::record_probe_error(&startup_probe, &err);
                                        if (status_error_is_connection_refused(&err)
                                            && !http_seen.load(Ordering::Relaxed))
                                            || status_error_is_torii_query_backpressure(&err)
                                        {
                                            debug!(
                                                error = %err,
                                                debug = ?err,
                                                "get status failed"
                                            );
                                        } else {
                                            log_status_warning(
                                                &warn_gate,
                                                || warn!(
                                                    error = %err,
                                                    debug = ?err,
                                                    "get status failed"
                                                ),
                                                || debug!(
                                                    error = %err,
                                                    debug = ?err,
                                                    "get status failed"
                                                ),
                                            );
                                        }
                                        if let Some(snapshot) =
                                            detect_block_height_from_storage(&storage_dir, min_height)
                                        {
                                            let mut status = Status {
                                                blocks: snapshot.total,
                                                blocks_non_empty: snapshot.non_empty,
                                                ..Status::default()
                                            };
                                            if let Some(peers) =
                                                NetworkPeer::last_status_peers(&startup_probe)
                                            {
                                                status.peers = peers;
                                                let _ = NetworkPeer::record_probe_status(
                                                    &startup_probe,
                                                    &status,
                                                );
                                            }
                                            log_status_warning(
                                                &warn_gate,
                                                || warn!(
                                                    snapshot = ?snapshot,
                                                    "using storage snapshot for initial status; Torii HTTP not reachable yet"
                                                ),
                                                || debug!(
                                                    snapshot = ?snapshot,
                                                    "using storage snapshot for initial status; Torii HTTP not reachable yet"
                                                ),
                                            );
                                            Ok((status, StatusSource::Storage))
                                        } else {
                                            Err(err)
                                        }
                                    }
                                }
                            }
                        }
                    };
                    let (status, source) = if status_timeout == Duration::ZERO {
                        tokio::select! {
                            status = retry_with_backoff(status_backoff) => status,
                            changed = fatal_rx.changed() => {
                                if changed.is_ok() && *fatal_rx.borrow() {
                                    debug!("fatal notify received while waiting for initial status");
                                }
                                return;
                            }
                        }
                    } else {
                        let status = tokio::select! {
                            status = retry_with_backoff_for(status_timeout, status_backoff) => status,
                            changed = fatal_rx.changed() => {
                                if changed.is_ok() && *fatal_rx.borrow() {
                                    debug!("fatal notify received while waiting for initial status");
                                }
                                return;
                            }
                        };
                        match status {
                            Ok(status) => status,
                            Err(_) => {
                                warn!(
                                    ?status_timeout,
                                    "timed out waiting for /status; falling back to storage snapshot"
                                );
                                let mut status = if let Some(snapshot) =
                                    detect_block_height_from_storage(&storage_dir, 0)
                                {
                                    Status {
                                        blocks: snapshot.total,
                                        blocks_non_empty: snapshot.non_empty,
                                        ..Status::default()
                                    }
                                } else {
                                    Status::default()
                                };
                                if let Some(peers) =
                                    NetworkPeer::last_status_peers(&startup_probe)
                                {
                                    status.peers = peers;
                                    let _ =
                                        NetworkPeer::record_probe_status(&startup_probe, &status);
                                }
                                (status, StatusSource::Storage)
                            }
                        }
                    };
                    last_progress = Instant::now();
                    let status_snapshot = status.clone();
                    let mut block_height = BlockHeight::from(status);
                    storage_min_height.store(block_height.total, Ordering::Relaxed);
                    let mut http_unreachable_warned = false;
                    if http_gate.on_status(source) {
                        http_seen.store(true, Ordering::Relaxed);
                        let _ = events_tx.send(PeerLifecycleEvent::ServerStarted);
                        info!(
                            ?status_snapshot,
                            torii_addr = %torii_addr.as_str(),
                            "server started via HTTP"
                        );
                    } else {
                        log_status_warning(
                            &warn_gate,
                            || warn!(
                                torii_addr = %torii_addr.as_str(),
                                ?status_snapshot,
                                "startup status derived from storage snapshot; waiting for Torii HTTP readiness"
                            ),
                            || debug!(
                                torii_addr = %torii_addr.as_str(),
                                ?status_snapshot,
                                "startup status derived from storage snapshot; waiting for Torii HTTP readiness"
                            ),
                        );
                    }
                    let _ = block_height_tx.send_replace(Some(block_height));
                    if block_height.total >= 1 {
                        info!(
                            snapshot = ?block_height,
                            "block watcher attached after genesis; subscribing from next height"
                        );
                        // Keep this task running so once_block* observers see future blocks.
                    }
                    // Avoid submitting synthetic transactions right after startup.
                    // Early side-effects here can cause racey counters in tests that fetch
                    // status via different codecs back-to-back.
                    loop {
                        let mut fallback_interval = tokio::time::interval(STATUS_FALLBACK_INTERVAL);
                        let poll_client = client.clone();
                        loop {
                            tokio::select! {
                                _ = fallback_interval.tick() => {
                                    if !is_running.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    let status = tokio::select! {
                                        result = async { poll_client.status().get().await } => result.map_err(Report::from),
                                        changed = fatal_rx.changed() => {
                                            if changed.is_ok() && *fatal_rx.borrow() {
                                                debug!("fatal notify received during status poll");
                                            }
                                            return;
                                        }
                                    };
                                    let status = match status {
                                        Ok(status) => {
                                            if http_gate.on_status(StatusSource::Http) {
                                                http_seen.store(true, Ordering::Relaxed);
                                                let _ = events_tx.send(PeerLifecycleEvent::ServerStarted);
                                                info!(
                                                    torii_addr = %torii_addr.as_str(),
                                                    "Torii HTTP became reachable"
                                                );
                                            }
                                            last_progress = Instant::now();
                                            let _ = NetworkPeer::record_probe_status(
                                                &startup_probe,
                                                &status,
                                            );
                                            status
                                        }
                                        Err(err) => {
                                        if (status_error_is_connection_refused(&err)
                                            && !http_seen.load(Ordering::Relaxed))
                                            || status_error_is_torii_query_backpressure(&err)
                                        {
                                            debug!(
                                                error = %err,
                                                debug = ?err,
                                                "fallback status poll failed"
                                            );
                                        } else if warn_gate.should_warn() {
                                            warn!(
                                                error = %err,
                                                debug = ?err,
                                                "fallback status poll failed"
                                            );
                                        } else {
                                            debug!(
                                                error = %err,
                                                debug = ?err,
                                                "fallback status poll failed"
                                            );
                                        }
                                        // Fall back to on-disk observation so scenarios can progress even if Torii
                                        // is slow to accept HTTP connections.
                                        if let Some(snapshot) =
                                            detect_block_height_from_storage(&storage_dir, block_height.total)
                                                && (snapshot.total > block_height.total
                                                    || snapshot.non_empty > block_height.non_empty)
                                        {
                                            if let Some(peers) =
                                                NetworkPeer::last_status_peers(&startup_probe)
                                            {
                                                let status = Status {
                                                    blocks: snapshot.total,
                                                    blocks_non_empty: snapshot.non_empty,
                                                    peers,
                                                    ..Status::default()
                                                };
                                                let _ = NetworkPeer::record_probe_status(
                                                    &startup_probe,
                                                    &status,
                                                );
                                            }
                                            block_height = snapshot;
                                            block_height_tx.send_modify(|slot| match slot {
                                                Some(current) => *current = snapshot,
                                                None => *slot = Some(snapshot),
                                            });
                                            storage_min_height
                                                .store(block_height.total, Ordering::Relaxed);
                                            last_progress = Instant::now();
                                            continue;
                                        }
                                        if !http_gate.http_seen()
                                            && let Some(deadline) = http_deadline
                                            && Instant::now() >= deadline
                                        {
                                            if !http_unreachable_warned {
                                                warn!(
                                                    torii_addr = %torii_addr.as_str(),
                                                    ?status_timeout,
                                                    "Torii HTTP not reachable from internal startup poll; continuing while storage-observed progress advances"
                                                );
                                                http_unreachable_warned = true;
                                            }
                                        }
                                        if status_timeout != Duration::ZERO
                                            && last_progress.elapsed() >= status_timeout
                                        {
                                            warn!(?status_timeout, "status watchdog expired; requesting shutdown");
                                            let _ = fatal_tx.send(true);
                                            return;
                                        }
                                        continue;
                                    }
                                };
                                    let snapshot = BlockHeight::from(status);
                                    if snapshot.total > block_height.total
                                        || snapshot.non_empty > block_height.non_empty
                                    {
                                        block_height = snapshot;
                                        storage_min_height
                                            .store(block_height.total, Ordering::Relaxed);
                                        block_height_tx.send_modify(|slot| match slot {
                                            Some(current) => {
                                                *current = snapshot;
                                            }
                                            None => *slot = Some(snapshot),
                                        });
                                    }
                                }
                                changed = fatal_rx.changed() => {
                                    if changed.is_ok() && *fatal_rx.borrow() {
                                        debug!("fatal notify received in blocks watchdog");
                                    }
                                    return;
                                }
                            }
                        }
                        if is_normal_shutdown_started.load(Ordering::Relaxed) {
                            info!("block stream closed normally after shutdown");
                            break
                        } else {
                            debug!("blocks stream closed without shutdown; retrying soon");
                            const RETRY: Duration = Duration::from_millis(1000);
                            tokio::time::sleep(RETRY).await;
                        }
                    }
                }
                .instrument(span),
            );
        }
        *run_guard = Some(PeerRun {
            tasks,
            shutdown: shutdown_tx,
            fatal_tx: fatal_tx.clone(),
            pid,
            #[cfg(unix)]
            broker_child,
        });
        Ok(())
    }
    /// Forcefully kills the running peer if it was started.
    ///
    /// Returns `true` if a running peer was found and shutdown logic was executed.
    pub async fn shutdown_if_started(&self) -> bool {
        let mut guard = self.run.lock().await;
        let Some(mut run) = (*guard).take() else {
            return false;
        };
        // Immediately drop the running flag so watchdog loops and status polls exit promptly.
        self.is_running.store(false, Ordering::Relaxed);
        // Wake any background watchers so they stop promptly during shutdown.
        let _ = run.fatal_tx.send(true);
        let _ = run.shutdown.send(());
        let join_all = async {
            while let Some(res) = run.tasks.join_next().await {
                if let Err(err) = res {
                    if err.is_cancelled() {
                        debug!("run task cancelled during shutdown");
                    } else if err.is_panic() {
                        warn!(error = %err, "run task panicked during shutdown");
                    }
                }
            }
        };
        if timeout(PEER_SHUTDOWN_TIMEOUT, join_all).await.is_err() {
            warn!("timed out waiting for peer tasks; aborting remaining tasks");
            if let Some(pid) = run.pid.filter(|pid| *pid > 0) {
                #[cfg(target_family = "unix")]
                {
                    use nix::{sys::signal, unistd::Pid};
                    if let Err(err) =
                        signal::kill(Pid::from_raw(pid as i32), signal::Signal::SIGKILL)
                    {
                        warn!(pid, error = %err, "failed to force-kill hung peer process");
                    }
                }
                #[cfg(not(target_family = "unix"))]
                {
                    warn!(
                        pid,
                        "unable to force-kill hung peer process on this platform"
                    );
                }
            }
            run.tasks.abort_all();
            let drain_aborted = async {
                while let Some(res) = run.tasks.join_next().await {
                    if let Err(err) = res
                        && err.is_panic()
                    {
                        warn!(error = %err, "aborted task panicked during shutdown");
                    }
                }
            };
            if timeout(PEER_SHUTDOWN_TIMEOUT, drain_aborted).await.is_err() {
                warn!("timed out waiting for aborted peer tasks; continuing shutdown");
            }
        }
        #[cfg(unix)]
        if let Some(mut broker_child) = run.broker_child.take() {
            disposable_runtime_provider_broker::stop_disposable_broker(&mut broker_child).await;
        }
        true
    }
    /// Forcefully kills the running peer
    ///
    /// # Panics
    /// If peer was not started.
    pub async fn shutdown(&self) {
        assert!(
            self.shutdown_if_started().await,
            "peer is not running, nothing to shut down"
        );
    }
    /// Like [`Self::start`], but also ensures that startup progresses far enough for tests.
    ///
    /// By default it waits for a `ServerStarted` lifecycle event (driven by `/status` success).
    /// During genesis bootstrap, if Torii remains unavailable but the peer has durably written
    /// block 1 to Kura and keeps running, this method falls back to storage-observed process
    /// readiness after a grace period so slow/contended hosts do not deadlock peer launch. This
    /// low-level fallback does not prove that world state has applied the block.
    ///
    /// Note: This method still does not wait for arbitrary later block commits; use higher-level
    /// helpers (e.g., `Network::start_all` or explicit `once_block`) if you need that.
    pub async fn start_checked<T: AsRef<Table>>(
        &self,
        config_layers: impl Iterator<Item = T>,
        genesis: Option<&GenesisBlock>,
    ) -> Result<()> {
        let genesis = PreparedPeerGenesis::prepare_optional(genesis).await?;
        self.start_checked_prepared(config_layers, genesis.as_ref())
            .await
    }

    async fn start_checked_prepared<T: AsRef<Table>>(
        &self,
        config_layers: impl Iterator<Item = T>,
        genesis: Option<&PreparedPeerGenesis>,
    ) -> Result<()> {
        let mut events = self.events();
        let has_genesis = genesis.is_some();
        self.start_prepared(config_layers, genesis).await?;
        let context = self
            .startup_context_summary()
            .unwrap_or_else(|| "<startup context not initialized>".to_string());
        let started_at = Instant::now();
        let mut fallback_poll = tokio::time::interval(START_CHECKED_FALLBACK_POLL_INTERVAL);
        fallback_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Ok(PeerLifecycleEvent::ServerStarted) => return Ok(()),
                    Ok(PeerLifecycleEvent::Terminated { status }) => {
                        let err = if let Some(preview) = self.stderr_preview() {
                            eyre!(
                                "Peer exited unexpectedly ({status:?}); {context}; stderr preview:\n{preview}"
                            )
                        } else {
                            eyre!("Peer exited unexpectedly ({status:?}); {context}")
                        };
                        return Err(err);
                    }
                    Ok(PeerLifecycleEvent::Killed) => {
                        let err = if let Some(preview) = self.stderr_preview() {
                            eyre!("Peer was killed before startup; {context}; stderr preview:\n{preview}")
                        } else {
                            eyre!("Peer was killed before startup; {context}")
                        };
                        return Err(err);
                    }
                    Ok(PeerLifecycleEvent::Spawned | PeerLifecycleEvent::BlockApplied { .. }) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(eyre!("Peer event channel closed before startup; {context}"));
                    }
                },
                _ = fallback_poll.tick(), if has_genesis => {
                    let elapsed = started_at.elapsed();
                    if start_checked_storage_fallback_ready(
                        has_genesis,
                        elapsed,
                        self.is_running(),
                        self.has_observed_block(1),
                    ) {
                        warn!(
                            ?elapsed,
                            mnemonic = self.mnemonic(),
                            "peer startup fallback: block 1 observed via best-effort snapshot before Torii /status readiness"
                        );
                        return Ok(());
                    }
                }
            }
        }
    }
    /// Subscribe on peer lifecycle events.
    pub fn events(&self) -> broadcast::Receiver<PeerLifecycleEvent> {
        self.events.subscribe()
    }
    /// Wait _once_ an event matches a predicate.
    ///
    /// ```ignore
    /// use iroha_test_network::{Network, NetworkBuilder, PeerLifecycleEvent};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let network = NetworkBuilder::new().build();
    ///     let peer = network.peer();
    ///
    ///     tokio::join!(
    ///         peer.start(network.config_layers(), None),
    ///         peer.once(|event| matches!(event, PeerLifecycleEvent::ServerStarted))
    ///     );
    /// }
    /// ```
    ///
    /// It is a narrowed version of [`Self::events`].
    pub async fn once<F>(&self, f: F)
    where
        F: Fn(PeerLifecycleEvent) -> bool,
    {
        let mut rx = self.events();
        loop {
            tokio::select! {
                Ok(event) = rx.recv() => {
                    if f(event) { break }
                }
            }
        }
    }
    /// Wait until peer's block height reaches N (total blocks, including genesis).
    ///
    /// Resolves immediately if peer is already running _and_ has at least N blocks committed. This
    /// treats the genesis block as progress even if it is empty, avoiding hangs when waiting for
    /// `once_block(1)` on nodes that commit a structurally empty genesis.
    pub async fn once_block(&self, n: u64) {
        self.once_block_with(|height| height.total >= n).await
    }
    /// Wait until peer's block height passes the given predicate.
    ///
    /// Resolves immediately if peer is running _and_ the predicate passes.
    pub async fn once_block_with<F: Fn(BlockHeight) -> bool>(&self, f: F) {
        let mut recv = self.block_height.subscribe();
        if recv.borrow().map(&f).unwrap_or(false) {
            return;
        }
        if let Some(snapshot) = self.best_effort_block_height()
            && f(snapshot)
        {
            return;
        }
        let mut storage_poll = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                changed = recv.changed() => {
                    changed.expect("could fail only if the peer is dropped");
                    if recv.borrow_and_update().map(&f).unwrap_or(false) {
                        break;
                    }
                }
                _ = storage_poll.tick() => {
                    if let Some(snapshot) = self
                        .best_effort_block_height()
                        .filter(|snapshot| f(*snapshot))
                    {
                        self.block_height.send_modify(|slot| match slot {
                            Some(current) => {
                                if snapshot.total > current.total
                                    || snapshot.non_empty > current.non_empty
                                {
                                    *current = snapshot;
                                }
                            }
                            None => *slot = Some(snapshot),
                        });
                        break;
                    }
                }
            }
        }
    }
    /// Generated mnemonic string, useful for logs
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }
    fn has_committed_block(&self, height: u64) -> bool {
        height > 0
            && detect_block_height_from_storage(&self.kura_store_dir(), 0)
                .is_some_and(|snapshot| snapshot.total >= height)
    }
    fn has_observed_block(&self, height: u64) -> bool {
        height > 0
            && self
                .best_effort_block_height()
                .is_some_and(|snapshot| snapshot.total >= height)
    }
    pub fn public_key(&self) -> &PublicKey {
        self.key_pair.public_key()
    }
    pub fn account_id(&self) -> AccountId {
        AccountId::new(self.streaming_public_key().clone())
    }
    pub fn streaming_key_pair(&self) -> &KeyPair {
        &self.streaming_key_pair
    }
    pub fn streaming_public_key(&self) -> &PublicKey {
        self.streaming_key_pair.public_key()
    }
    /// Return the dedicated Ed25519 key pair used by this peer's SoraNet transport.
    pub fn soranet_transport_key_pair(&self) -> &KeyPair {
        &self.soranet_transport_key_pair
    }
    /// Return the dedicated SoraNet transport public key.
    pub fn soranet_transport_public_key(&self) -> &PublicKey {
        self.soranet_transport_key_pair.public_key()
    }
    pub fn bls_key_pair(&self) -> Option<&KeyPair> {
        self.bls_key_pair.as_ref()
    }
    pub fn bls_public_key(&self) -> Option<&PublicKey> {
        self.bls_key_pair.as_ref().map(KeyPair::public_key)
    }
    pub fn bls_pop(&self) -> Option<&[u8]> {
        self.bls_pop.as_deref()
    }
    pub fn genesis_pop(&self) -> Option<GenesisTopologyEntry> {
        self.bls_public_key().and_then(|pk| {
            self.bls_pop()
                .map(|pop| GenesisTopologyEntry::new(PeerId::new(pk.clone()), pop.to_vec()))
        })
    }
    /// Generated [`PeerId`]
    pub fn id(&self) -> PeerId {
        self.network_peer_id()
    }
    /// [`PeerId`] representing the BLS peer identity used in topology and PoP validation.
    pub fn network_peer_id(&self) -> PeerId {
        PeerId::new(self.key_pair.public_key().clone())
    }
    pub fn p2p_address(&self) -> SocketAddr {
        socket_addr!(127.0.0.1:**self.port_p2p)
    }
    /// Torii HTTP API socket address (host + port).
    pub fn api_address(&self) -> SocketAddr {
        socket_addr!(127.0.0.1:**self.port_api)
    }
    /// Torii HTTP URL for this peer, e.g. `http://127.0.0.1:8080`.
    pub fn torii_url(&self) -> String {
        format!("http://{}", self.api_address())
    }
    /// Path to this peer's Kura store directory.
    ///
    /// By default tests configure Kura with `store_dir = "./storage"` relative to the peer run dir.
    /// This helper returns `<peer_dir>/storage` matching that configuration.
    pub fn kura_store_dir(&self) -> PathBuf {
        if let Ok(context) = self.start_context.lock() {
            if let Some(context) = context.as_ref() {
                return context.kura_store_dir.clone();
            }
        }
        self.dir.join("storage")
    }
    fn should_reset_kura_for_bootstrap(has_genesis: bool, run_num: usize) -> bool {
        // A genesis file on the initial start indicates a bootstrap run that should start from
        // empty storage. Subsequent starts for the same peer are restarts and must preserve any
        // existing state even if a genesis payload is provided.
        has_genesis && run_num == 1
    }
    fn prepare_kura_storage_dir(
        &self,
        storage_dir: &Path,
        reset_for_bootstrap: bool,
    ) -> Result<()> {
        if reset_for_bootstrap {
            match fs::symlink_metadata(storage_dir) {
                Ok(meta) => {
                    if meta.is_dir() && !meta.file_type().is_symlink() {
                        fs::remove_dir_all(storage_dir).wrap_err_with(|| {
                            format!(
                                "failed to clear storage directory {} before bootstrap",
                                storage_dir.display()
                            )
                        })?;
                    } else {
                        fs::remove_file(storage_dir).or_else(|err| {
                            if err.kind() == ErrorKind::NotFound {
                                Ok(())
                            } else {
                                Err(err)
                            }
                        })?;
                    }
                }
                Err(err) if err.kind() != ErrorKind::NotFound => {
                    return Err(err).wrap_err_with(|| {
                        format!(
                            "failed to inspect storage path {} before bootstrap",
                            storage_dir.display()
                        )
                    });
                }
                Err(_) => {}
            }
        }
        match fs::symlink_metadata(storage_dir) {
            Ok(meta) => {
                if !meta.is_dir() {
                    fs::remove_file(storage_dir)
                        .or_else(|err| {
                            if err.kind() == ErrorKind::IsADirectory {
                                fs::remove_dir_all(storage_dir)
                            } else {
                                Err(err)
                            }
                        })
                        .wrap_err_with(|| {
                            format!(
                                "failed to remove non-directory path at {} before Kura startup",
                                storage_dir.display()
                            )
                        })?;
                }
            }
            Err(err) if err.kind() != ErrorKind::NotFound => {
                return Err(err).wrap_err_with(|| {
                    format!("failed to inspect storage path {}", storage_dir.display())
                });
            }
            Err(_) => {}
        }
        fs::create_dir_all(storage_dir).wrap_err_with(|| {
            format!(
                "failed to prepare Kura storage directory at {}",
                storage_dir.display()
            )
        })
    }
    fn storage_snapshot(&self) -> PeerStorageSnapshot {
        let kura_dir = self.kura_store_dir();
        let has_block_1 = self.has_committed_block(1);
        PeerStorageSnapshot::capture(kura_dir, has_block_1)
    }
    /// Check whether the peer is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }
    /// Return the operating-system process identifier for the current peer run.
    ///
    /// The identifier is present only after the child has been spawned and is
    /// cleared when the run terminates. Release evidence callers must combine
    /// this value with a fresh health check instead of treating PID presence as
    /// proof that the process remains alive.
    pub async fn process_id(&self) -> Option<u32> {
        self.run.lock().await.as_ref().and_then(|run| run.pid)
    }
    /// Create a distinct client for an explicit account, using the attached peer policy.
    pub fn client_for(&self, account_id: &AccountId, account_private_key: PrivateKey) -> Client {
        Client::from_client(self.async_client_for(account_id, account_private_key))
            .expect("peer blocking client runtime should initialize")
    }
    fn async_client_for(
        &self,
        account_id: &AccountId,
        account_private_key: PrivateKey,
    ) -> AsyncClient {
        tracing::debug!(
            mnemonic = %self.mnemonic,
            port = %self.port_api,
            "TEST_NETWORK client"
        );
        let identity = self
            .client_config
            .get()
            .expect("peer must be attached to a network before creating clients");
        let policy = self.client_policy();
        let status_timeout = policy.status_timeout;
        let request_timeout = policy.request_timeout;
        let ttl = policy.ttl;
        let config = ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::inline(
                Table::new()
                    .write("chain", identity.chain.to_string())
                    .write("network_id", identity.network_id.to_string())
                    .write(
                        ["account", "chain_discriminant"],
                        i64::from(identity.chain_discriminant),
                    )
                    .write(
                        ["account", "public_key"],
                        account_id.expect_single_signatory().to_string(),
                    )
                    .write(
                        ["account", "private_key"],
                        ExposedPrivateKey(account_private_key.clone()).to_string(),
                    )
                    .write(
                        ["transaction", "status_timeout_ms"],
                        i64::try_from(status_timeout.as_millis())
                            .expect("status timeout fits in i64"),
                    )
                    .write(
                        "torii_request_timeout_ms",
                        i64::try_from(request_timeout.as_millis())
                            .expect("request timeout fits in i64"),
                    )
                    .write(
                        ["transaction", "time_to_live_ms"],
                        i64::try_from(ttl.as_millis()).expect("ttl fits in i64"),
                    )
                    .write("torii_url", format!("http://127.0.0.1:{}", self.port_api)),
            ))
            .read_and_complete::<iroha::config::UserConfig>()
            .expect("peer client config should be valid")
            .parse()
            .expect("peer client config should be valid");
        let mut builder = AsyncClient::builder(config);
        builder.operator_key_pair = Some(self.key_pair.clone());
        builder
            .build()
            .expect("peer account context should be valid")
    }
    /// Clone Alice's retained client context for this peer.
    ///
    /// Network identity, operator authority and deadline policy are fixed at network
    /// attachment. Clones share connection pools and the owned blocking runtime;
    /// each call still performs fresh requests and applies the configured deadlines.
    pub fn client(&self) -> Client {
        self.retained_client().clone()
    }
    fn client_policy(&self) -> &PeerClientPolicy {
        &self
            .client_config
            .get()
            .expect("peer must be attached to a network before creating clients")
            .policy
    }
    fn retained_client(&self) -> &Client {
        self.retained_client
            .get_or_init(|| self.client_for(&ALICE_ID, ALICE_KEYPAIR.private_key().clone()))
    }
    pub async fn status(&self) -> Result<Status> {
        let client = self.retained_client().client().clone();
        let result = client.status().get().await.map_err(Report::from);
        match &result {
            Ok(status) => self.record_status_success(status),
            Err(error) => self.record_status_failure(error),
        }
        result
    }
    async fn sumeragi_startup_snapshot(&self) -> Result<PeerSumeragiSnapshot> {
        let client = self.client();
        let result = read_on_dedicated_thread(move || client.client().get_sumeragi_status()).await;
        match result {
            Ok(status) => Ok(Self::record_probe_sumeragi_status(
                &self.startup_probe,
                &status,
            )),
            Err(error) => {
                Self::record_probe_sumeragi_error(&self.startup_probe, &format!("{error:?}"));
                Err(error)
            }
        }
    }
    fn record_status_success(&self, status: &Status) {
        let _ = Self::record_probe_status(&self.startup_probe, status);
    }
    fn record_status_failure(&self, error: &Report) {
        Self::record_probe_error(&self.startup_probe, error);
    }
    /// Best-effort durable Kura height based on the latest observation and the canonical
    /// block-hash journal. Callers requiring applied world-state authority must use `/status`.
    pub fn best_effort_block_height(&self) -> Option<BlockHeight> {
        let observed = *self.block_height.borrow();
        let current_total = observed.map(|height| height.total).unwrap_or(0);
        let from_storage = detect_block_height_from_storage(&self.kura_store_dir(), current_total);
        match (observed, from_storage) {
            (Some(current), Some(storage)) => Some(BlockHeight {
                total: current.total.max(storage.total),
                non_empty: current.non_empty.max(storage.non_empty),
            }),
            (Some(current), None) => Some(current),
            (None, Some(storage)) => Some(storage),
            (None, None) => None,
        }
    }
    /// Last observed peer count from `/status`, if any.
    pub fn last_known_peers(&self) -> Option<u64> {
        self.startup_probe
            .lock()
            .ok()
            .and_then(|probe| probe.last_status.as_ref().map(|snapshot| snapshot.peers))
    }
    /// Path to the most recent stdout log file for this peer run, if any.
    pub fn latest_stdout_log_path(&self) -> Option<PathBuf> {
        self.latest_run_log_path_suffix("stdout")
    }
    /// Path to the most recent stderr log file for this peer run, if any.
    pub fn latest_stderr_log_path(&self) -> Option<PathBuf> {
        self.latest_run_log_path_suffix("stderr")
    }
    fn latest_run_log_path_suffix(&self, which: &str) -> Option<PathBuf> {
        // Files are named as run-<n>-stdout.log or run-<n>-stderr.log
        let mut best: Option<(usize, PathBuf)> = None;
        if let Ok(read) = std::fs::read_dir(&self.dir) {
            for entry in read.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    // quick prefix/suffix match
                    if name.starts_with("run-") && name.ends_with(&format!("-{which}.log")) {
                        // extract the number between run- and -<which>.log
                        let mid = &name[4..name.len() - (which.len() + 5)];
                        // mid is like "<n>"
                        if let Ok(n) = mid.parse::<usize>() {
                            match best {
                                Some((best_n, _)) if n <= best_n => {}
                                _ => best = Some((n, path.clone())),
                            }
                        }
                    }
                }
            }
        }
        best.map(|(_, p)| p)
    }
    /// Snapshot the most recent stderr output captured for this peer run.
    ///
    /// Returns a short preview (last few lines) to avoid flooding logs.
    fn stderr_preview(&self) -> Option<String> {
        let guard = self
            .stderr_live
            .lock()
            .expect("stderr live buffer should not be poisoned");
        summarize_peer_stderr(&guard.buffer).map(|summary| summary.preview)
    }
    fn log_snapshot(&self) -> PeerLogSnapshot {
        let stdout_log = self.latest_stdout_log_path();
        let stdout_summary = stdout_log.as_deref().and_then(summarize_peer_stdout_file);
        let stdout_preview_line_count = stdout_summary
            .as_ref()
            .map(|inner| inner.preview.lines().count());
        let stdout_truncated = stdout_summary.as_ref().is_some_and(|inner| inner.truncated);
        let stderr_log = self.latest_stderr_log_path();
        let (stderr_run_id, summary) = {
            let guard = self
                .stderr_live
                .lock()
                .expect("stderr live buffer should not be poisoned");
            (guard.run_id, summarize_peer_stderr(&guard.buffer))
        };
        let stderr_preview_line_count = summary.as_ref().map(|inner| inner.preview.lines().count());
        let stderr_total_lines = summary.as_ref().map(|inner| inner.total_lines);
        let stderr_truncated = summary.as_ref().is_some_and(|inner| inner.truncated);
        PeerLogSnapshot {
            stdout_log,
            stdout_preview: stdout_summary.map(|inner| inner.preview),
            stdout_preview_line_count,
            stdout_truncated,
            stderr_log,
            stderr_preview: summary.map(|inner| inner.preview),
            stderr_preview_line_count,
            stderr_total_lines,
            stderr_truncated,
            stderr_run_id,
        }
    }
    pub fn blocks(&self) -> watch::Receiver<Option<BlockHeight>> {
        self.block_height.subscribe()
    }
    fn startup_state(&self, index: usize) -> PeerStartupState {
        let receiver = self.blocks();
        let last_block = *receiver.borrow();
        let probe = self
            .startup_probe
            .lock()
            .expect("startup probe should not be poisoned")
            .clone();
        PeerStartupState {
            index,
            mnemonic: self.mnemonic().to_string(),
            is_running: self.is_running(),
            last_block,
            logs: self.log_snapshot(),
            status_snapshot: probe.last_status,
            status_error: probe.last_status_error,
            status_unix_timestamp_ms: probe.last_status_unix_ms,
            sumeragi_snapshot: probe.last_sumeragi,
            sumeragi_error: probe.last_sumeragi_error,
            sumeragi_unix_timestamp_ms: probe.last_sumeragi_unix_ms,
            storage: self.storage_snapshot(),
        }
    }
    fn write_base_config(&self) {
        let cfg = self.base_config_table();
        std::fs::write(
            self.dir.join("config.base.toml"),
            toml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        self.ensure_rans_tables();
    }
    fn base_config_table(&self) -> Table {
        let p2p_literal = self.p2p_address().to_literal();
        let torii_literal = self.api_address().to_literal();
        let config = Table::new()
            .write("public_key", self.key_pair.public_key().to_string())
            .write(
                "private_key",
                ExposedPrivateKey(self.key_pair.private_key().clone()).to_string(),
            )
            .write(
                "soranet_transport_public_key",
                self.soranet_transport_public_key().to_string(),
            )
            .write(
                "soranet_transport_private_key",
                ExposedPrivateKey(self.soranet_transport_key_pair.private_key().clone())
                    .to_string(),
            )
            .write(
                ["streaming", "identity_public_key"],
                self.streaming_public_key().to_string(),
            )
            .write(
                ["streaming", "identity_private_key"],
                ExposedPrivateKey(self.streaming_key_pair.private_key().clone()).to_string(),
            )
            .write(["network", "address"], p2p_literal.clone())
            .write(["network", "public_address"], p2p_literal)
            .write(["torii", "address"], torii_literal)
            // Allow larger uploads for DA/IBC-heavy fixtures.
            .write(
                ["torii", "max_content_len"],
                toml::Value::Integer(16 * 1024 * 1024),
            );
        #[cfg(unix)]
        if let (Some(endpoint), Some(binding)) = (
            self.disposable_runtime_provider_broker_endpoint(),
            self.disposable_beacon_provider_binding(),
        ) {
            return config
                .write(
                    ["runtime_provider_broker", "endpoint_path"],
                    endpoint
                        .to_str()
                        .expect("validated broker endpoint is UTF-8")
                        .to_owned(),
                )
                .write(
                    ["sumeragi", "global_beacon_partial_signer_provider_handle"],
                    binding.handle,
                )
                .write(
                    ["sumeragi", "global_beacon_partial_signer_provider_revision"],
                    i64::try_from(binding.revision)
                        .expect("validated broker revision fits TOML i64"),
                )
                .write(
                    [
                        "sumeragi",
                        "global_beacon_partial_signer_provider_policy_digest_hex",
                    ],
                    lowercase_hex(&binding.policy_digest),
                );
        }
        config
    }
    fn ensure_rans_tables(&self) {
        let dst = self
            .dir
            .join("codec")
            .join("rans")
            .join("tables")
            .join("rans_seed0.toml");
        let parent = dst
            .parent()
            .expect("codec rANS table has a parent directory");
        fs::create_dir_all(parent).expect("create codec/rans/tables dir");
        match fs::symlink_metadata(&dst) {
            Ok(metadata) => {
                assert!(
                    metadata.file_type().is_file(),
                    "peer codec rANS tables must be a regular file"
                );
                if fs::read(&dst).expect("read peer codec rANS tables") == DEFAULT_RANS_TABLES {
                    return;
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => panic!("inspect peer codec rANS tables: {error}"),
        }
        // Source captures are read-only. Materialize owned bytes instead of inheriting
        // source permissions, and replace stale tables without truncating a read-only file.
        let mut staged = tempfile::NamedTempFile::new_in(parent)
            .expect("create owner-private codec rANS table fixture");
        staged
            .write_all(DEFAULT_RANS_TABLES)
            .expect("write canonical codec rANS tables");
        staged
            .persist(&dst)
            .expect("publish canonical codec rANS tables into peer dir");
    }
    fn canonical_genesis_bytes(block: &GenesisBlock) -> Result<Vec<u8>> {
        let framed = block
            .0
            .encode_wire()
            .map_err(color_eyre::Report::new)
            .wrap_err("encode genesis block with Norito header")?;
        let deframed =
            iroha_data_model::block::deframe_versioned_signed_block_bytes(framed.as_slice())
                .map_err(color_eyre::Report::new)
                .wrap_err("deframe genesis sanity check")?;
        let versioned = block.0.encode_versioned();
        assert_eq!(deframed.bare_versioned.as_ref(), versioned.as_slice());
        Ok(framed)
    }
    fn restart_genesis_file(&self, has_genesis: bool) -> Option<PathBuf> {
        if has_genesis {
            return None;
        }
        fs::read_dir(&self.dir)
            .ok()?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if !entry.file_type().ok()?.is_file() {
                    return None;
                }
                let file_name = path.file_name()?.to_str()?;
                let run = file_name
                    .strip_prefix("run-")?
                    .strip_suffix("-genesis.nrt")?
                    .parse::<usize>()
                    .ok()?;
                Some((run, path))
            })
            .max_by_key(|(run, _)| *run)
            .map(|(_, path)| path)
    }
    async fn write_run_config<T: AsRef<Table>>(
        &self,
        cfg_extra_layers: impl Iterator<Item = T>,
        genesis: Option<&PreparedPeerGenesis>,
        existing_genesis_path: Option<&Path>,
        run: usize,
    ) -> Result<PathBuf> {
        // Recreate the base layer for every run to avoid stale/missing configs
        // when previous runs left the directory partially populated.
        self.write_base_config();
        let extra_layers: Vec<_> = cfg_extra_layers
            .enumerate()
            .map(|(i, table)| {
                (
                    format!("run-{run}-config.layer-{i}.toml"),
                    table.as_ref().clone(),
                )
            })
            .collect();
        for (path, table) in &extra_layers {
            tokio::fs::write(self.dir.join(path), toml::to_string(table)?).await?;
        }
        let mut final_config = Table::new().write(
            "extends",
            // should be written on peer's initialisation
            iter::once("config.base.toml".to_string())
                .chain(extra_layers.into_iter().map(|(path, _)| path))
                .collect::<Vec<String>>(),
        );
        if let Some(block) = genesis {
            let path = self.dir.join(format!("run-{run}-genesis.nrt"));
            final_config =
                final_config.write(["genesis", "file"], path.to_string_lossy().to_string());
            tokio::fs::write(path, block.bytes.as_ref()).await?;
        } else if let Some(path) = existing_genesis_path {
            final_config =
                final_config.write(["genesis", "file"], path.to_string_lossy().to_string());
        }
        let path = self.dir.join(format!("run-{run}-config.toml"));
        tokio::fs::write(&path, toml::to_string(&final_config)?).await?;
        Ok(path)
    }
}
/// Retry an async operation with exponential backoff.
///
/// - Starts at 50ms and doubles up to a 1s cap.
/// - Retries indefinitely until the operation returns `Ok`.
async fn retry_with_backoff_for<F, Fut, T, E>(
    duration: Duration,
    op: F,
) -> Result<T, tokio::time::error::Elapsed>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    timeout(duration, retry_with_backoff(op)).await
}
async fn retry_with_backoff<F, Fut, T, E>(mut op: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut delay = Duration::from_millis(50);
    loop {
        match op().await {
            Ok(value) => return value,
            Err(_) => {
                tokio::time::sleep(delay).await;
                delay = core::cmp::min(delay.saturating_mul(2), Duration::from_secs(1));
            }
        }
    }
}
/// Compare by ID
impl PartialEq for NetworkPeer {
    fn eq(&self, other: &Self) -> bool {
        self.key_pair.eq(&other.key_pair)
    }
}
pub struct NetworkPeerBuilder {
    mnemonic: String,
    seed: Option<Vec<u8>>,
    parliament_beacon_signer_mode: Option<ParliamentBeaconSignerMode>,
}
impl NetworkPeerBuilder {
    #[allow(clippy::new_without_default)] // has side effects
    pub fn new() -> Self {
        Self {
            // `petname` may occasionally yield multi-word parts or stray newline characters.
            // Replace all whitespace with underscores to conform to `Name` restrictions.
            mnemonic: petname::petname(2, "_")
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join("_"),
            seed: None,
            parliament_beacon_signer_mode: None,
        }
    }
    pub fn with_seed(mut self, seed: Option<impl Into<Vec<u8>>>) -> Self {
        self.seed = seed.map(Into::into);
        self
    }
    fn with_parliament_beacon_signer_mode(
        mut self,
        mode: Option<ParliamentBeaconSignerMode>,
    ) -> Self {
        self.parliament_beacon_signer_mode = mode;
        self
    }
    pub fn build(self, env: &Environment) -> NetworkPeer {
        self.build_with_program(env, Program::Irohad)
    }
    fn build_with_program(self, env: &Environment, program: Program) -> NetworkPeer {
        let NetworkPeerBuilder {
            mnemonic,
            seed,
            parliament_beacon_signer_mode,
        } = self;
        assert_eq!(
            parliament_beacon_signer_mode.is_some(),
            matches!(program, Program::IrohadParliamentSigners),
            "a Parliament beacon signer mode belongs only to its feature-isolated daemon",
        );
        let streaming_key_pair = seed
            .as_ref()
            .map(|seed_bytes| checked_key_pair_from_seed(seed_bytes.clone(), Algorithm::Ed25519))
            .unwrap_or_else(|| {
                KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
                    .expect("generate checked random streaming keypair")
            });
        let soranet_transport_key_pair = seed.as_ref().map_or_else(
            || random_soranet_transport_key_pair_distinct_from(&streaming_key_pair),
            |seed_bytes| {
                let pair =
                    checked_soranet_transport_key_pair_from_seed(seed_bytes.clone());
                assert_ne!(
                    pair.public_key(),
                    streaming_key_pair.public_key(),
                    "domain-separated SoraNet transport identity must differ from streaming identity"
                );
                pair
            },
        );
        let bls_key = if let Some(mut seed_bytes) = seed.clone() {
            seed_bytes.extend_from_slice(b":bls");
            checked_key_pair_from_seed(seed_bytes, Algorithm::BlsNormal)
        } else {
            KeyPair::try_random_with_algorithm(Algorithm::BlsNormal)
                .expect("generate checked random BLS keypair")
        };
        let pop =
            iroha_crypto::bls_normal_pop_prove(bls_key.private_key()).expect("BLS PoP generation");
        let key_pair = bls_key.clone();
        let bls_key_pair = Some(bls_key);
        let bls_pop = Some(pop);
        let port_p2p = AllocatedPort::new();
        let port_api = AllocatedPort::new();
        let dir = env.dir.join(&mnemonic);
        std::fs::create_dir_all(&dir).unwrap();
        let private_settlement_route_control =
            matches!(program, Program::IrohadPrivateSettlementRoutes)
                .then(|| {
                    PrivateSettlementRouteControl::create(
                        dir.join("consensus-private-settlement-route-control"),
                    )
                    .expect("create private consensus private-settlement-route-control directory")
                })
                .map(Arc::new);
        println!("TEST_NETWORK peer dir {} -> {}", mnemonic, dir.display());
        let (events, _rx) = broadcast::channel(32);
        let (block_height, _rx) = watch::channel(None);
        let span = info_span!("peer", mnemonic);
        span.in_scope(|| {
            info!(
                dir=%dir.display(),
                port_p2p=%port_p2p,
                port_api=%port_api,
                "Build peer",
            )
        });
        let peer = NetworkPeer {
            mnemonic,
            span,
            key_pair,
            client_config: Arc::new(OnceLock::new()),
            retained_client: Arc::new(OnceLock::new()),
            streaming_key_pair,
            soranet_transport_key_pair,
            bls_key_pair,
            bls_pop,
            dir,
            run: Default::default(),
            runs_count: Default::default(),
            is_running: Default::default(),
            events,
            block_height,
            stderr_live: Arc::new(StdMutex::new(LiveStderrState::default())),
            startup_probe: Arc::new(StdMutex::new(PeerStartupProbe::default())),
            start_context: Arc::new(StdMutex::new(None)),
            program,
            parliament_beacon_signer_mode,
            private_settlement_route_control,
            #[cfg(unix)]
            disposable_runtime_provider_broker: Arc::new(StdMutex::new(None)),
            port_p2p: Arc::new(port_p2p),
            port_api: Arc::new(port_api),
        };
        peer.write_base_config();
        peer
    }
}
/// Prints collected STDERR on drop.
///
/// Used to avoid loss of useful data in case of task abortion before it is printed directly.
struct PeerStderrBuffer {
    span: tracing::Span,
    buffer: Arc<StdMutex<LiveStderrState>>,
    log_path: PathBuf,
}
const PEER_STDERR_PREVIEW_MAX_LINES: usize = 25;
const PEER_STDERR_PREVIEW_MAX_CHARS: usize = 3_072;
const PEER_STDOUT_PREVIEW_READ_BYTES: u64 = 64 * 1_024;
struct StderrSummary {
    preview: String,
    truncated: bool,
    total_lines: usize,
}
fn summarize_peer_stderr(buffer: &str) -> Option<StderrSummary> {
    let trimmed = buffer.trim_end_matches('\n');
    if trimmed.is_empty() {
        return None;
    }
    let total_lines = trimmed.lines().count();
    let start_line = total_lines.saturating_sub(PEER_STDERR_PREVIEW_MAX_LINES);
    let mut truncated = start_line > 0;
    let mut preview = trimmed
        .lines()
        .skip(start_line)
        .collect::<Vec<_>>()
        .join("\n");
    let preview_char_count = preview.chars().count();
    if preview_char_count > PEER_STDERR_PREVIEW_MAX_CHARS {
        truncated = true;
        let mut tail: Vec<char> = preview
            .chars()
            .rev()
            .take(PEER_STDERR_PREVIEW_MAX_CHARS)
            .collect();
        tail.reverse();
        preview = tail.into_iter().collect();
    }
    Some(StderrSummary {
        preview,
        truncated,
        total_lines,
    })
}
fn summarize_peer_stdout_file(path: &Path) -> Option<StderrSummary> {
    let mut file = fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    let start = length.saturating_sub(PEER_STDOUT_PREVIEW_READ_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::with_capacity(usize::try_from(length - start).ok()?);
    file.read_to_end(&mut bytes).ok()?;
    let decoded = String::from_utf8_lossy(&bytes);
    let tail = if start == 0 {
        decoded.as_ref()
    } else {
        decoded
            .find('\n')
            .map_or(decoded.as_ref(), |index| &decoded[index + 1..])
    };
    let decisive_excerpt = decisive_peer_stdout_excerpt(tail);
    let mut summary = summarize_peer_stderr(decisive_excerpt.as_deref().unwrap_or(tail))?;
    summary.truncated |= start > 0;
    Some(summary)
}
fn decisive_peer_stdout_excerpt(tail: &str) -> Option<String> {
    let lines = tail.lines().collect::<Vec<_>>();
    let failure_index = lines.iter().rposition(|line| {
        let normalized = line.to_ascii_lowercase();
        normalized.contains("failed closed")
            || normalized.contains("fail-closed")
            || normalized.contains("panicked at")
            || normalized.contains("fatal consensus")
            || normalized.contains("restart is required")
    })?;
    let failure_start = failure_index.saturating_sub(1);
    let failure_end = failure_index.saturating_add(5).min(lines.len());
    let trailing_start = lines.len().saturating_sub(6);
    if trailing_start <= failure_end {
        return None;
    }
    let mut excerpt = lines[trailing_start..].join("\n");
    excerpt.push_str("\n... decisive peer failure ...\n");
    excerpt.push_str(&lines[failure_start..failure_end].join("\n"));
    Some(excerpt)
}
impl PeerStderrBuffer {
    fn new(span: tracing::Span, log_path: PathBuf, buffer: Arc<StdMutex<LiveStderrState>>) -> Self {
        Self {
            span,
            buffer,
            log_path,
        }
    }
    fn push_line(&self, line: &str) {
        if let Ok(mut guard) = self.buffer.lock() {
            guard.push_line(line);
        }
    }
}
impl Drop for PeerStderrBuffer {
    fn drop(&mut self) {
        if let Ok(guard) = self.buffer.lock()
            && let Some(summary) = summarize_peer_stderr(&guard.buffer)
        {
            self.span.in_scope(|| {
                info!(
                    run = ?guard.run_id,
                    path = %self.log_path.display(),
                    total_lines = summary.total_lines,
                    truncated = summary.truncated,
                    "peer emitted stderr; full contents stored on disk"
                );
                if !summary.preview.is_empty() {
                    debug!(
                        run = ?guard.run_id,
                        truncated = summary.truncated,
                        preview_lines = summary.preview.lines().count(),
                        preview = %summary.preview,
                        "peer stderr tail preview"
                    );
                }
            });
        }
    }
}
#[cfg(test)]
include!("lib/peer_runtime_tests.rs");
struct PeerExit {
    child: Child,
    span: tracing::Span,
    is_running: Arc<AtomicBool>,
    is_normal_shutdown_started: Arc<AtomicBool>,
    events: broadcast::Sender<PeerLifecycleEvent>,
    block_height: watch::Sender<Option<BlockHeight>>,
    fatal_rx: watch::Receiver<bool>,
    stderr_log_ready: Arc<Notify>,
    stderr_live: Arc<StdMutex<LiveStderrState>>,
}
impl PeerExit {
    async fn monitor(mut self, shutdown: oneshot::Receiver<()>) -> Result<()> {
        let status = if *self.fatal_rx.borrow() {
            self.span
                .in_scope(|| debug!("forcing peer shutdown after fatal signal"));
            self.shutdown_or_kill().await?
        } else {
            tokio::select! {
                status = self.child.wait() => status?,
                _ = shutdown => self.shutdown_or_kill().await?,
                changed = self.fatal_rx.changed() => {
                    if changed.is_ok() && *self.fatal_rx.borrow() {
                        self.span.in_scope(|| debug!("forcing peer shutdown after fatal signal"));
                    }
                    self.shutdown_or_kill().await?
                }
            }
        };
        self.await_log_flushes().await;
        println!("TEST_NETWORK peer exited with status {status:?}");
        self.dump_last_stderr();
        self.span.in_scope(|| info!(%status, "Peer terminated"));
        let _ = self.events.send(PeerLifecycleEvent::Terminated { status });
        self.is_running.store(false, Ordering::Relaxed);
        self.block_height.send_modify(|x| *x = None);
        Ok(())
    }
    async fn await_log_flushes(&self) {
        self.wait_log(&self.stderr_log_ready, "stderr").await;
    }
    async fn wait_log(&self, notify: &Arc<Notify>, label: &'static str) {
        if (timeout(LOG_FLUSH_TIMEOUT, notify.notified()).await).is_err() {
            let fatal_shutdown = *self.fatal_rx.borrow();
            let normal_shutdown = self.is_normal_shutdown_started.load(Ordering::Relaxed);
            if fatal_shutdown || normal_shutdown {
                self.span.in_scope(|| {
                    debug!(
                        log = label,
                        fatal_shutdown,
                        normal_shutdown,
                        "timed out waiting for log flush during shutdown"
                    )
                });
            } else {
                self.span
                    .in_scope(|| warn!(log = label, "timed out waiting for log flush"));
            }
        }
    }
    async fn shutdown_or_kill(&mut self) -> Result<ExitStatus> {
        use nix::{sys::signal, unistd::Pid};
        const TIMEOUT: Duration = Duration::from_secs(5);
        const QUIT_GRACE: Duration = Duration::from_secs(1);
        self.is_normal_shutdown_started
            .store(true, Ordering::Relaxed);
        if let Some(status) = self
            .child
            .try_wait()
            .wrap_err("failed to poll child exit status before shutdown")?
        {
            self.span.in_scope(
                || info!(%status, "child already exited before shutdown signal could be delivered"),
            );
            return Ok(status);
        }
        if self.child.id().is_none() {
            self.span.in_scope(|| {
                info!("child already exited before shutdown signal could be delivered")
            });
            return self.child.wait().await.wrap_err("wait failure");
        }
        self.span.in_scope(|| info!("sending SIGTERM"));
        signal::kill(
            Pid::from_raw(self.child.id().expect("checked child id above") as i32),
            signal::Signal::SIGTERM,
        )
        .wrap_err("failed to send SIGTERM")?;
        if let Ok(status) = timeout(TIMEOUT, self.child.wait()).await {
            self.span.in_scope(|| info!("exited gracefully"));
            return status.wrap_err("wait failure");
        };
        // If graceful shutdown stalls, attempt to capture a backtrace (where supported).
        #[cfg(target_family = "unix")]
        if let Some(pid) = self.child.id() {
            if let Err(err) = signal::kill(Pid::from_raw(pid as i32), signal::Signal::SIGQUIT)
                .map_err(Report::from)
            {
                self.span
                    .in_scope(|| warn!(?err, pid, "failed to send SIGQUIT before killing"));
            } else {
                self.span
                    .in_scope(|| debug!(pid, "sent SIGQUIT to peer for diagnostics"));
                if let Ok(status) = timeout(QUIT_GRACE, self.child.wait()).await {
                    self.span.in_scope(|| info!("exited after SIGQUIT"));
                    return status.wrap_err("wait failure");
                }
            }
        }
        self.span
            .in_scope(|| warn!("process didn't terminate after {TIMEOUT:?}, killing"));
        timeout(TIMEOUT, async move {
            self.child.kill().await.expect("not a recoverable failure");
            self.child.wait().await
        })
        .await
        .wrap_err("didn't terminate after SIGKILL")?
        .wrap_err("wait failure")
    }
    fn dump_last_stderr(&self) {
        let guard = self
            .stderr_live
            .lock()
            .expect("stderr live buffer should not be poisoned");
        if guard.buffer.is_empty() {
            eprintln!("TEST_NETWORK peer stderr was empty before exit");
            return;
        }
        let preview = summarize_peer_stderr(&guard.buffer)
            .map(|summary| summary.preview)
            .unwrap_or_else(|| "<stderr summary unavailable>".to_string());
        eprintln!("TEST_NETWORK peer stderr tail:\n{preview}");
    }
}
fn pipeline_dirs(storage_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(entries) = fs::read_dir(storage_dir.join("blocks")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path.join("pipeline"));
            }
        }
    }
    dirs
}
#[cfg(test)]
include!("lib/block_height_test_support.rs");
/// Composite block height representation
#[derive(Debug, Copy, Clone)]
pub struct BlockHeight {
    /// Total blocks
    pub total: u64,
    /// Non-empty blocks
    pub non_empty: u64,
}
impl From<Status> for BlockHeight {
    fn from(value: Status) -> Self {
        Self {
            total: value.blocks,
            non_empty: value.blocks_non_empty,
        }
    }
}
impl BlockHeight {
    /// Shorthand to use with e.g. [`once_blocks_sync`].
    pub fn predicate_non_empty(non_empty_height: u64) -> impl Fn(BlockHeight) -> bool + Clone {
        move |value| value.non_empty >= non_empty_height
    }
    /// Predicate that waits for the overall block height, regardless of whether
    /// the blocks were empty.
    pub fn predicate_total(total_height: u64) -> impl Fn(BlockHeight) -> bool + Clone {
        move |value| value.total >= total_height
    }
}
fn detect_block_height_from_storage(storage_dir: &Path, current_total: u64) -> Option<BlockHeight> {
    let hashes_path =
        iroha_core::kura::Kura::canonical_storage_path(storage_dir).join("blocks.hashes");
    let metadata = fs::metadata(hashes_path).ok()?;
    let hash_bytes = u64::try_from(CryptoHash::LENGTH).ok()?;
    if !metadata.is_file() || metadata.len() % hash_bytes != 0 {
        return None;
    }
    let hashes_height = metadata.len() / hash_bytes;
    // Pipeline recovery sidecars are written before consensus finality and their compact index
    // contains a fixed header in addition to entry records.  They are useful diagnostics, but
    // neither their presence nor their byte length proves that a block was applied. Only Kura's
    // canonical hash journal proves durable storage height; applied readiness must additionally
    // pass Torii's authoritative `/status` height barrier.
    let max_height = hashes_height;
    if max_height > current_total {
        Some(BlockHeight {
            total: max_height,
            non_empty: max_height,
        })
    } else {
        None
    }
}
/// Wait until [`NetworkPeer::once_block`] resolves for all peers.
///
/// Fails early if some peer terminates.
pub async fn once_blocks_sync(
    peers: impl Iterator<Item = &NetworkPeer>,
    f: impl Fn(BlockHeight) -> bool + Clone,
) -> Result<()> {
    let mut futures = peers
        .map(|x| {
            let f = f.clone();
            async move {
                let mut storage_poll = tokio::time::interval(Duration::from_millis(250));
                loop {
                    tokio::select! {
                        () = x.once_block_with(f.clone()) => {
                            return Ok(());
                        },
                        () = x.once(|e| matches!(e, PeerLifecycleEvent::Terminated { .. })) => {
                            return Err(eyre!("Peer terminated"));
                        },
                        _ = storage_poll.tick() => {
                            if let Some(snapshot) = detect_block_height_from_storage(&x.kura_store_dir(), 0)
                                && f(snapshot)
                            {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        })
        .collect::<FuturesUnordered<_>>();
    loop {
        match futures.next().await {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(e),
            None => return Ok(()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    include!("genesis_validation_cache_tests.rs");
    include!("profile_account_defaults_tests.rs");
    include!("peer_client_profile_tests.rs");
    include!("peer_client_context_tests.rs");
    include!("genesis_profile_tests.rs");
    include!("sora_profile_tests.rs");
    use iroha_config::parameters::defaults;
    use iroha_core::sumeragi::consensus::compute_consensus_parameters_fingerprint;
    use iroha_crypto::Algorithm;
    use iroha_data_model::{
        block::{decode_framed_signed_block, deframe_versioned_signed_block_bytes},
        isi::{Instruction, SetParameter},
        parameter::{Parameter, system::consensus_metadata},
        transaction::{Executable, ExecutableBatchItem},
    };
    use iroha_version::{Version, codec::EncodeVersioned};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        collections::HashSet,
        env,
        ffi::{OsStr, OsString},
        fs, io,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };
    use tempfile::tempdir;
    use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
    use toml::Value as TomlValue;
    static LOG_ENV_GUARD: AsyncMutex<()> = AsyncMutex::const_new(());
    /// Serializes async tests that override `TEST_NETWORK_BIN_*` variables so they
    /// cannot leak into concurrently running cases.
    static PROGRAM_BIN_ENV_GUARD: AsyncMutex<()> = AsyncMutex::const_new(());
    /// Serializes mutations of client timeout overrides.
    static CLIENT_ENV_GUARD: AsyncMutex<()> = AsyncMutex::const_new(());
    /// Serializes mutations of config env overrides so local parsing ignores host overrides.
    static CONFIG_ENV_GUARD: AsyncMutex<()> = AsyncMutex::const_new(());
    /// Serializes network permit env overrides so tests do not race on temp directories.
    ///
    /// Tests needing both guards must acquire `CONFIG_ENV_GUARD` first.
    static NETWORK_PERMIT_ENV_GUARD: AsyncMutex<()> = AsyncMutex::const_new(());
    fn lock_env_guard(mutex: &'static AsyncMutex<()>) -> AsyncMutexGuard<'static, ()> {
        mutex.blocking_lock()
    }
    async fn lock_env_guard_async(mutex: &'static AsyncMutex<()>) -> AsyncMutexGuard<'static, ()> {
        mutex.lock().await
    }
    fn skip_network_tests(test_name: &str) -> bool {
        static LOOPBACK_BIND_ALLOWED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let can_bind = *LOOPBACK_BIND_ALLOWED
            .get_or_init(|| std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok());
        if can_bind {
            false
        } else {
            eprintln!("skipping {test_name}: environment denies binding TCP sockets on 127.0.0.1");
            true
        }
    }
    fn set_env_var<K, V>(key: K, value: V)
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        unsafe { std::env::set_var(key, value) }
    }
    fn remove_env_var<K>(key: K)
    where
        K: AsRef<OsStr>,
    {
        unsafe { std::env::remove_var(key) }
    }
    struct EnvVarRestore {
        key: &'static str,
        previous: Option<OsString>,
    }
    impl EnvVarRestore {
        fn set<K: AsRef<OsStr>>(key: &'static str, value: K) -> Self {
            let previous = env::var_os(key);
            set_env_var(key, value);
            Self { key, previous }
        }
    }
    impl Drop for EnvVarRestore {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                set_env_var(self.key, value);
            } else {
                remove_env_var(self.key);
            }
        }
    }
    #[test]
    fn config_env_override_keys_include_core_settings() {
        let keys = config_env_override_keys();
        assert!(keys.contains(&"API_ADDRESS"));
        assert!(keys.contains(&"P2P_ADDRESS"));
        assert!(keys.contains(&"CHAIN"));
        assert!(!keys.is_empty());
    }
    #[test]
    fn strip_config_env_overrides_marks_keys_for_removal() {
        struct DummyCommand {
            removed: Vec<String>,
        }
        impl CommandEnv for DummyCommand {
            fn env_remove(&mut self, key: &str) {
                self.removed.push(key.to_string());
            }
        }
        let mut cmd = DummyCommand {
            removed: Vec::new(),
        };
        strip_config_env_overrides(&mut cmd);
        let removed: HashSet<_> = cmd.removed.into_iter().collect();
        assert!(removed.contains("API_ADDRESS"));
        assert!(removed.contains("P2P_ADDRESS"));
        assert!(removed.contains("CHAIN"));
    }
    #[test]
    fn network_parallelism_env_override_applies() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let _parallel_guard = EnvVarRestore::set(NETWORK_PARALLELISM_ENV, "2");
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "0");
        assert_eq!(network_parallelism_limit(), 2);
    }
    #[test]
    fn network_parallelism_defaults_to_serial_networks() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        remove_env_var(NETWORK_PARALLELISM_ENV);
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "0");
        assert_eq!(
            network_parallelism_limit(),
            DEFAULT_NETWORK_PARALLELISM_LIMIT
        );
    }
    #[test]
    fn serialization_overrides_parallelism_limit() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let _parallel_guard = EnvVarRestore::set(NETWORK_PARALLELISM_ENV, "4");
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "1");
        assert_eq!(network_parallelism_limit(), 1);
    }
    #[test]
    fn status_results_satisfy_predicate_requires_all_successes() {
        let predicate = BlockHeight::predicate_total(2);
        assert!(Network::status_results_satisfy_predicate(
            vec![
                Ok::<BlockHeight, ()>(BlockHeight {
                    total: 2,
                    non_empty: 1
                }),
                Ok::<BlockHeight, ()>(BlockHeight {
                    total: 3,
                    non_empty: 2
                }),
            ],
            &predicate
        ));
        assert!(!Network::status_results_satisfy_predicate(
            vec![Ok::<BlockHeight, ()>(BlockHeight {
                total: 1,
                non_empty: 1
            })],
            &predicate
        ));
        assert!(!Network::status_results_satisfy_predicate(
            vec![Err::<BlockHeight, ()>(())],
            &predicate
        ));
    }
    #[test]
    fn network_permit_wait_timeout_env_override_applies() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        remove_env_var(NETWORK_PERMIT_WAIT_TIMEOUT_ENV);
        assert_eq!(
            network_permit_wait_timeout(),
            Some(NETWORK_PERMIT_WAIT_TIMEOUT_DEFAULT)
        );
        let _timeout_guard = EnvVarRestore::set(NETWORK_PERMIT_WAIT_TIMEOUT_ENV, "250ms");
        assert_eq!(
            network_permit_wait_timeout(),
            Some(Duration::from_millis(250))
        );
        drop(_timeout_guard);
        let _timeout_guard = EnvVarRestore::set(NETWORK_PERMIT_WAIT_TIMEOUT_ENV, "0");
        assert_eq!(network_permit_wait_timeout(), None);
    }
    #[test]
    fn permit_dir_env_override_wins() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let dir = tempdir().expect("permit dir");
        let _dir_guard = EnvVarRestore::set(NETWORK_PERMIT_DIR_ENV, dir.path());
        assert_eq!(permit_dir(), dir.path());
    }
    #[cfg(unix)]
    #[test]
    fn default_permit_dir_is_namespaced_by_parent_pid() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        remove_env_var(NETWORK_PERMIT_DIR_ENV);
        let dir = permit_dir();
        let expected_prefix = std::env::temp_dir().join("iroha_test_network_permits");
        assert!(
            dir.starts_with(&expected_prefix),
            "default permit dir should use temp root {expected_prefix:?}, got {dir:?}"
        );
        let expected_namespace = format!("ppid-{}", nix::unistd::getppid().as_raw());
        assert_eq!(
            dir.file_name().and_then(OsStr::to_str),
            Some(expected_namespace.as_str()),
            "default permit dir should be namespaced by parent pid"
        );
    }
    #[test]
    fn describe_permit_holders_reports_lock_owner() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let dir = tempdir().expect("permit dir");
        let _dir_guard = EnvVarRestore::set(NETWORK_PERMIT_DIR_ENV, dir.path());
        let path = dir.path().join("permit-0.lock");
        let mut file = fs::File::create(&path).expect("create permit lock");
        writeln!(file, "pid={}", std::process::id()).expect("write pid");
        writeln!(file, "started=1").expect("write started");
        let holders = describe_permit_holders(1);
        assert!(
            holders.contains("slot=0"),
            "expected slot details in holder summary: {holders}"
        );
        assert!(
            holders.contains(&format!("pid={}", std::process::id())),
            "expected pid details in holder summary: {holders}"
        );
        #[cfg(unix)]
        assert!(
            holders.contains("alive=yes"),
            "expected liveness details in holder summary: {holders}"
        );
    }
    #[test]
    fn acquire_network_permit_panics_after_wait_timeout() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let dir = tempdir().expect("permit dir");
        let _dir_guard = EnvVarRestore::set(NETWORK_PERMIT_DIR_ENV, dir.path());
        let _parallel_guard = EnvVarRestore::set(NETWORK_PARALLELISM_ENV, "1");
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "0");
        let _timeout_guard = EnvVarRestore::set(NETWORK_PERMIT_WAIT_TIMEOUT_ENV, "25ms");
        let path = dir.path().join("permit-0.lock");
        let mut file = fs::File::create(&path).expect("create permit lock");
        writeln!(file, "pid={}", std::process::id()).expect("write pid");
        writeln!(file, "started=1").expect("write started");
        let started = std::time::Instant::now();
        let panic = match std::panic::catch_unwind(acquire_network_permit) {
            Ok(_) => panic!("acquire_network_permit should panic when wait timeout elapses"),
            Err(panic) => panic,
        };
        let panic_message = panic
            .downcast_ref::<&str>()
            .map(std::string::ToString::to_string)
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<missing panic message>".to_owned());
        assert!(
            panic_message.contains("timed out"),
            "panic should explain permit wait timeout, got: {panic_message}"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(20),
            "permit wait should not panic before timeout elapsed"
        );
    }
    #[test]
    fn peer_startup_timeout_override_is_applied() {
        if skip_network_tests("peer_startup_timeout_override_is_applied") {
            return;
        }
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_min_peers(4)
                .with_peer_startup_timeout(Duration::from_secs(300)),
        );
        assert_eq!(network.peer_startup_timeout(), Duration::from_secs(300));
    }
    #[test]
    fn sync_timeout_override_is_applied() {
        if skip_network_tests("sync_timeout_override_is_applied") {
            return;
        }
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_min_peers(4)
                .with_sync_timeout(Duration::from_secs(300)),
        );
        assert_eq!(network.sync_timeout(), Duration::from_secs(300));
    }
    #[test]
    fn with_base_seed_if_unset_sets_only_when_missing() {
        let builder = NetworkBuilder::new().with_base_seed_if_unset("seed-a");
        assert_eq!(builder.seed.as_deref(), Some("seed-a"));
        let builder = NetworkBuilder::new()
            .with_base_seed("seed-b")
            .with_base_seed_if_unset("seed-c");
        assert_eq!(builder.seed.as_deref(), Some("seed-b"));
    }
    #[test]
    fn cloned_builder_recipe_allocates_an_isolated_network_environment() {
        if skip_network_tests("cloned_builder_recipe_allocates_an_isolated_network_environment") {
            return;
        }
        let recipe = NetworkBuilder::new()
            .with_peers(4)
            .with_base_seed("fresh-network-retry-recipe");
        let first = build_with_isolated_permit(recipe.clone());
        let second = build_with_isolated_permit(recipe);
        assert_ne!(
            first.env_dir(),
            second.env_dir(),
            "each build of one retry recipe must own a fresh filesystem root"
        );
        assert_eq!(
            first
                .peers()
                .iter()
                .map(NetworkPeer::id)
                .collect::<Vec<_>>(),
            second
                .peers()
                .iter()
                .map(NetworkPeer::id)
                .collect::<Vec<_>>(),
            "fresh attempts must preserve the deterministic test topology"
        );
        for (first_peer, second_peer) in first.peers().iter().zip(second.peers()) {
            assert_ne!(first_peer.dir, second_peer.dir);
            assert_ne!(first_peer.p2p_address(), second_peer.p2p_address());
            assert_ne!(first_peer.api_address(), second_peer.api_address());
        }
    }
    #[test]
    fn peer_startup_timeout_applies_per_peer_floor() {
        if skip_network_tests("peer_startup_timeout_applies_per_peer_floor") {
            return;
        }
        let _timeout_guard = EnvVarRestore::set("IROHA_TEST_PEER_START_TIMEOUT_SECS", "10");
        let network = build_with_isolated_permit(NetworkBuilder::new().with_min_peers(4));
        let expected = Duration::from_secs(
            PEER_STARTUP_TIMEOUT_PER_PEER_SECS.saturating_mul(network.peers().len() as u64),
        );
        assert_eq!(network.peer_startup_timeout(), expected);
    }
    #[test]
    fn network_permit_creates_and_clears_lock_file() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let dir = tempdir().expect("permit dir");
        let _dir_guard = EnvVarRestore::set(NETWORK_PERMIT_DIR_ENV, dir.path());
        let _parallel_guard = EnvVarRestore::set(NETWORK_PARALLELISM_ENV, "1");
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "0");
        let permit = acquire_network_permit();
        let file_count = fs::read_dir(dir.path())
            .expect("permit dir listing")
            .count();
        assert_eq!(file_count, 1, "expected a single permit file");
        drop(permit);
        let file_count = fs::read_dir(dir.path())
            .expect("permit dir listing")
            .count();
        assert_eq!(file_count, 0, "permit file should be removed");
    }
    #[cfg(unix)]
    #[test]
    fn stale_permit_file_is_reclaimed() {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let dir = tempdir().expect("permit dir");
        let _dir_guard = EnvVarRestore::set(NETWORK_PERMIT_DIR_ENV, dir.path());
        let _parallel_guard = EnvVarRestore::set(NETWORK_PARALLELISM_ENV, "1");
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "0");
        let path = dir.path().join("permit-0.lock");
        let mut file = fs::File::create(&path).expect("stale permit file");
        writeln!(file, "pid={}", i32::MAX).expect("write pid");
        let permit = try_acquire_file_permit(1).expect("expected reclaimed permit");
        drop(permit);
    }
    #[cfg(unix)]
    #[test]
    fn pid_alive_detects_current_and_dead_processes() {
        assert_eq!(pid_alive(std::process::id()), Some(true));
        assert_eq!(pid_alive(i32::MAX as u32), Some(false));
    }
    #[test]
    fn sora_profile_detection_does_not_augment_a_supplied_pop_roster() {
        let key_pair = KeyPair::try_from_seed(
            b"test-network supplied Sora-profile detection PoP".to_vec(),
            Algorithm::BlsNormal,
        )
        .expect("deterministic BLS fixture");
        let public_key = key_pair.public_key().to_string();
        let pop =
            iroha_crypto::bls_normal_pop_prove(key_pair.private_key()).expect("derive fixture PoP");
        let mut pop_entry = Table::new();
        pop_entry.insert("public_key".into(), Value::String(public_key.clone()));
        pop_entry.insert(
            "pop_hex".into(),
            Value::String(format!("0x{}", hex_lower(&pop))),
        );
        let mut table = Table::new().write(
            ["trusted_peers_pop"],
            Value::Array(vec![Value::Table(pop_entry)]),
        );
        ensure_sora_profile_trusted_peer_pop(&mut table);
        let entries = table
            .get("trusted_peers_pop")
            .and_then(Value::as_array)
            .expect("supplied PoP roster remains an array");
        assert_eq!(entries.len(), 1, "profile detection must not add a voter");
        assert_eq!(
            entries[0]
                .as_table()
                .and_then(|entry| entry.get("public_key"))
                .and_then(Value::as_str),
            Some(public_key.as_str())
        );
    }
    #[test]
    fn config_requires_sora_profile_ignores_env_overrides() {
        let _guard = lock_env_guard(&CONFIG_ENV_GUARD);
        struct EnvRestore {
            key: &'static str,
            previous: Option<OsString>,
        }
        impl EnvRestore {
            fn set(key: &'static str, value: OsString) -> Self {
                let previous = env::var_os(key);
                set_env_var(key, value);
                Self { key, previous }
            }
            fn clear(key: &'static str) -> Self {
                let previous = env::var_os(key);
                remove_env_var(key);
                Self { key, previous }
            }
        }
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                if let Some(value) = self.previous.take() {
                    set_env_var(self.key, value);
                } else {
                    remove_env_var(self.key);
                }
            }
        }
        let _public_key_guard = EnvRestore::set(
            "PUBLIC_KEY",
            OsString::from(ALICE_KEYPAIR.public_key().to_string()),
        );
        let _private_key_guard = EnvRestore::clear("PRIVATE_KEY");
        let _fee_asset_guard = EnvRestore::set(
            "NEXUS_FEE_ASSET_ID",
            OsString::from("invalid-host-fee-selector"),
        );
        assert!(!config_requires_sora_profile(&[Table::new()]));
        let layer = Table::new().write(["torii", "sorafs", "storage", "enabled"], true);
        assert!(
            config_requires_sora_profile(&[layer]),
            "profile detection should not be influenced by host env overrides"
        );
    }
    #[tokio::test]
    async fn once_block_falls_back_to_storage_snapshot() {
        let dir = tempdir().expect("tempdir");
        let lane_dir = dir.path().join("storage/blocks/canonical");
        fs::create_dir_all(&lane_dir).expect("lane dir");
        fs::write(lane_dir.join("blocks.hashes"), vec![0u8; 64]).expect("committed block hashes");
        let (events_tx, _events_rx) = tokio::sync::broadcast::channel(4);
        let (block_height, _rx) = tokio::sync::watch::channel(None);
        let storage_root = dir.path().to_path_buf();
        let streaming_key_pair = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate once-block fallback streaming key");
        let soranet_transport_key_pair =
            random_soranet_transport_key_pair_distinct_from(&streaming_key_pair);
        let peer = NetworkPeer {
            mnemonic: "once-block-fallback".to_string(),
            span: tracing::Span::none(),
            key_pair: KeyPair::try_random().expect("generate once-block fallback peer key"),
            client_config: Arc::new(OnceLock::new()),
            retained_client: Arc::new(OnceLock::new()),
            streaming_key_pair,
            soranet_transport_key_pair,
            bls_key_pair: None,
            bls_pop: None,
            dir: storage_root,
            run: Arc::new(tokio::sync::Mutex::new(None)),
            runs_count: Arc::new(AtomicUsize::new(0)),
            is_running: Arc::new(AtomicBool::new(true)),
            events: events_tx,
            block_height,
            stderr_live: Arc::new(StdMutex::new(LiveStderrState::default())),
            startup_probe: Arc::new(StdMutex::new(PeerStartupProbe::default())),
            start_context: Arc::new(StdMutex::new(None)),
            program: Program::Irohad,
            parliament_beacon_signer_mode: None,
            private_settlement_route_control: None,
            #[cfg(unix)]
            disposable_runtime_provider_broker: Arc::new(StdMutex::new(None)),
            port_p2p: Arc::new(AllocatedPort::new()),
            port_api: Arc::new(AllocatedPort::new()),
        };
        let result = tokio::time::timeout(Duration::from_secs(1), peer.once_block(2)).await;
        assert!(
            result.is_ok(),
            "once_block should observe storage height via fallback"
        );
    }
    #[test]
    fn startup_status_height_is_the_applied_authority_barrier() {
        let height_zero = Status::default();
        assert!(
            !status_reaches_block_height(&height_zero, 1),
            "a successful height-zero status response cannot release startup"
        );
        let height_one = Status {
            blocks: 1,
            blocks_non_empty: 1,
            ..Status::default()
        };
        assert!(status_reaches_block_height(&height_one, 1));
        assert!(!status_reaches_block_height(&height_one, 2));
    }
    #[tokio::test]
    async fn wait_for_block_1_with_watchdog_rejects_kura_without_applied_status() {
        let dir = tempdir().expect("tempdir");
        let lane_dir = dir.path().join("storage/blocks/canonical");
        fs::create_dir_all(&lane_dir).expect("lane dir");
        fs::write(lane_dir.join("blocks.hashes"), vec![0u8; 32])
            .expect("durable Kura hash journal");
        let (events_tx, _events_rx) = tokio::sync::broadcast::channel(4);
        let (block_height, _rx) = tokio::sync::watch::channel(None);
        let streaming_key_pair = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate watchdog streaming key");
        let soranet_transport_key_pair =
            random_soranet_transport_key_pair_distinct_from(&streaming_key_pair);
        let client_config = Arc::new(OnceLock::new());
        assert!(
            client_config
                .set(PeerClientConfig {
                    chain: config::chain_id(),
                    network_id: NetworkId::from_genesis_hash(HashOf::<
                        iroha_data_model::block::BlockHeader,
                    >::from_untyped_unchecked(
                        CryptoHash::prehashed([0xA5; CryptoHash::LENGTH]),
                    )),
                    chain_discriminant: defaults::common::chain_discriminant(),
                    policy: PeerClientPolicy::from_env(),
                })
                .is_ok()
        );
        let peer = NetworkPeer {
            mnemonic: "wait-block-authority-barrier".to_string(),
            span: tracing::Span::none(),
            key_pair: KeyPair::try_random().expect("generate watchdog peer key"),
            client_config,
            retained_client: Arc::new(OnceLock::new()),
            streaming_key_pair,
            soranet_transport_key_pair,
            bls_key_pair: None,
            bls_pop: None,
            dir: dir.path().to_path_buf(),
            run: Arc::new(tokio::sync::Mutex::new(None)),
            runs_count: Arc::new(AtomicUsize::new(0)),
            is_running: Arc::new(AtomicBool::new(true)),
            events: events_tx,
            block_height,
            stderr_live: Arc::new(StdMutex::new(LiveStderrState::default())),
            startup_probe: Arc::new(StdMutex::new(PeerStartupProbe::default())),
            start_context: Arc::new(StdMutex::new(None)),
            program: Program::Irohad,
            parliament_beacon_signer_mode: None,
            private_settlement_route_control: None,
            #[cfg(unix)]
            disposable_runtime_provider_broker: Arc::new(StdMutex::new(None)),
            port_p2p: Arc::new(AllocatedPort::new()),
            port_api: Arc::new(AllocatedPort::new()),
        };
        assert!(peer.has_committed_block(1));
        let mnemonic = peer.mnemonic().to_string();
        let result = tokio::time::timeout(
            Duration::from_millis(750),
            Network::wait_for_block_1_with_watchdog(&peer, 0, &mnemonic, "test"),
        )
        .await;
        peer.is_running.store(false, Ordering::Relaxed);
        assert!(
            result.is_err(),
            "durable Kura height without authoritative applied status must keep startup pending"
        );
    }
    #[test]
    fn startup_snapshot_formats_compact_sumeragi_progress_state() {
        let dir = tempdir().expect("tempdir");
        let snapshot = PeerSumeragiSnapshot {
            height: 4,
            view: 2,
            stage: 1,
            high_qc_view: Some(1),
            level: 3,
            committed_height: 3,
            applied_height: 3,
            awaiting: false,
            signing: true,
            unanchored: false,
            halted: None,
        };
        let rendered = PeerStartupState {
            index: 3,
            mnemonic: "diagnostic-peer".to_string(),
            is_running: true,
            last_block: Some(BlockHeight {
                total: 0,
                non_empty: 0,
            }),
            logs: PeerLogSnapshot::default(),
            status_snapshot: Some(PeerStatusSnapshot::default()),
            status_error: None,
            status_unix_timestamp_ms: Some(1),
            sumeragi_snapshot: Some(snapshot),
            sumeragi_error: None,
            sumeragi_unix_timestamp_ms: Some(2),
            storage: PeerStorageSnapshot::capture(dir.path().join("storage"), false),
        }
        .to_string();
        for expected in [
            "sumeragi=ok(h4/v2/s1 level=3 lock=1 committed=3 applied=3",
            "awaiting=false signing=true unanchored=false halted=-)@2ms",
        ] {
            assert!(
                rendered.contains(expected),
                "startup diagnostic omitted `{expected}`: {rendered}"
            );
        }
    }
    /// Restores environment variable to its previous value when dropped.
    struct EnvVarGuard {
        key: &'static str,
        original: Option<OsString>,
    }
    impl EnvVarGuard {
        fn cleared(key: &'static str) -> Self {
            let original = env::var_os(key);
            remove_env_var(key);
            Self { key, original }
        }
    }
    #[test]
    fn cargo_build_enables_bundled_rans() {
        assert!(
            build_env_overrides()
                .iter()
                .any(|(key, value)| *key == "ENABLE_RANS_BUNDLES" && *value == "1")
        );
    }
    #[test]
    fn preflight_bind_detects_in_use_port() {
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(err) => {
                if err.kind() == io::ErrorKind::PermissionDenied {
                    eprintln!("skipping preflight_bind_detects_in_use_port: {err}");
                    return;
                }
                panic!("unexpected error binding ephemeral port: {err}");
            }
        };
        let addr = listener
            .local_addr()
            .expect("listener should expose local address");
        let addr = SocketAddr::from(addr);
        let result = preflight_bind_addresses([addr]);
        match result {
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {}
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping preflight check: {err}");
            }
            Err(err) => panic!("unexpected preflight bind error: {err}"),
            Ok(()) => panic!("preflight should fail when port is already in use"),
        }
    }
    #[test]
    fn bind_preflight_runs_only_before_first_start_attempt() {
        assert!(should_run_bind_preflight_for_runs_started(0));
        assert!(!should_run_bind_preflight_for_runs_started(1));
        assert!(!should_run_bind_preflight_for_runs_started(2));
    }
    #[test]
    fn startup_warn_gate_waits_for_grace() {
        let grace = Duration::from_millis(25);
        let gate = StartupWarnGate::new(grace);
        assert!(!gate.should_warn());
        thread::sleep(grace + Duration::from_millis(10));
        assert!(gate.should_warn());
        // Subsequent warnings should be throttled until the interval elapses.
        assert!(!gate.should_warn());
        thread::sleep(STARTUP_STATUS_WARN_INTERVAL);
        assert!(gate.should_warn());
    }
    #[test]
    fn status_error_is_connection_refused_checks_structured_transport_kind() {
        for (kind, expected) in [
            (
                iroha::TransportErrorKind::Io(ErrorKind::ConnectionRefused),
                true,
            ),
            (iroha::TransportErrorKind::Io(ErrorKind::AddrInUse), false),
            (iroha::TransportErrorKind::Other, false),
        ] {
            let report = Report::from(iroha::Error::Transport {
                operation: "diagnostic.status",
                kind,
                details: "Connection refused text must not decide classification".to_owned(),
            });
            assert_eq!(status_error_is_connection_refused(&report), expected);
            let nested = Err::<(), Report>(report)
                .wrap_err("client status probe failed")
                .unwrap_err();
            assert_eq!(status_error_is_connection_refused(&nested), expected);
        }
    }
    #[test]
    fn status_error_is_connection_refused_detects_io_error() {
        let err = std::io::Error::new(ErrorKind::ConnectionRefused, "refused");
        let report = Report::from(err);
        assert!(status_error_is_connection_refused(&report));
    }
    #[test]
    fn status_error_is_connection_refused_detects_nested_io_error() {
        let report = Err::<(), Report>(Report::from(std::io::Error::new(
            ErrorKind::ConnectionRefused,
            "refused",
        )))
        .wrap_err("client status probe failed")
        .unwrap_err();
        assert!(status_error_is_connection_refused(&report));
    }
    #[test]
    fn status_error_is_connection_refused_ignores_other_errors() {
        let err = std::io::Error::other("other");
        let report = Report::from(err);
        assert!(!status_error_is_connection_refused(&report));
    }
    #[test]
    fn status_error_is_connection_refused_ignores_nested_non_refusal_io_errors() {
        let report = Err::<(), Report>(Report::from(std::io::Error::new(
            ErrorKind::AddrInUse,
            "address already in use",
        )))
        .wrap_err("client status probe failed")
        .unwrap_err();
        assert!(!status_error_is_connection_refused(&report));
    }
    #[test]
    fn status_error_is_torii_query_backpressure_checks_structured_status_and_body() {
        for (status, body, expected) in [
            (429, b"Reached the limit of parallel queries".to_vec(), true),
            (
                503,
                b"Reached the limit of parallel queries".to_vec(),
                false,
            ),
            (429, b"another rate limit".to_vec(), false),
            (429, vec![0xff], false),
        ] {
            let report = Report::from(iroha::Error::Http {
                operation: "diagnostic.status",
                status,
                body,
                retry_after: None,
            });
            assert_eq!(status_error_is_torii_query_backpressure(&report), expected);
            let nested = Err::<(), Report>(report)
                .wrap_err("client status probe failed")
                .unwrap_err();
            assert_eq!(status_error_is_torii_query_backpressure(&nested), expected);
        }
    }
    #[test]
    fn status_error_is_torii_query_backpressure_detects_status_throttle() {
        let report = eyre!(
            "Norito decode failed: Unexpected status response; status: 429 Too Many Requests; response body: Reached the limit of parallel queries"
        );
        assert!(status_error_is_torii_query_backpressure(&report));
    }
    #[test]
    fn status_error_is_torii_query_backpressure_detects_nested_status_throttle() {
        let report = Err::<(), Report>(eyre!(
            "Unexpected status response; status: 429 Too Many Requests; response body: Reached the limit of parallel queries"
        ))
        .wrap_err("client status probe failed")
        .unwrap_err();
        assert!(status_error_is_torii_query_backpressure(&report));
    }
    #[test]
    fn status_error_is_torii_query_backpressure_ignores_other_throttles() {
        let report = eyre!("Unexpected status response; status: 429 Too Many Requests");
        assert!(!status_error_is_torii_query_backpressure(&report));
    }
    #[test]
    fn status_error_is_torii_query_backpressure_ignores_limit_phrase_without_429() {
        let report = eyre!("Reached the limit of parallel queries while validating locally");
        assert!(!status_error_is_torii_query_backpressure(&report));
    }
    #[test]
    fn status_error_is_torii_query_backpressure_ignores_split_status_and_limit_causes() {
        let report = Err::<(), Report>(eyre!("Reached the limit of parallel queries"))
            .wrap_err("Unexpected status response; status: 429 Too Many Requests")
            .unwrap_err();
        assert!(!status_error_is_torii_query_backpressure(&report));
    }
    #[test]
    fn torii_request_error_is_transient_checks_structured_transport_causes() {
        let deadline = iroha::Error::Timeout {
            operation: "diagnostic.status",
        };
        let cases = std::iter::once((deadline, true)).chain(
            [
                (
                    iroha::TransportErrorKind::Io(ErrorKind::ConnectionRefused),
                    true,
                ),
                (
                    iroha::TransportErrorKind::Io(ErrorKind::ConnectionReset),
                    true,
                ),
                (
                    iroha::TransportErrorKind::Io(ErrorKind::ConnectionAborted),
                    true,
                ),
                (iroha::TransportErrorKind::Io(ErrorKind::BrokenPipe), true),
                (
                    iroha::TransportErrorKind::Io(ErrorKind::UnexpectedEof),
                    true,
                ),
                (iroha::TransportErrorKind::Io(ErrorKind::TimedOut), true),
                (
                    iroha::TransportErrorKind::Io(ErrorKind::PermissionDenied),
                    false,
                ),
                (iroha::TransportErrorKind::Io(ErrorKind::InvalidData), false),
                (iroha::TransportErrorKind::Other, false),
            ]
            .into_iter()
            .map(|(kind, expected)| {
                (
                    iroha::Error::Transport {
                        operation: "diagnostic.status",
                        kind,
                        details: "opaque diagnostic".to_owned(),
                    },
                    expected,
                )
            }),
        );
        for (error, expected) in cases {
            let report = Report::from(error);
            assert_eq!(torii_request_error_is_transient(&report), expected);
            let nested = report.wrap_err("status probe");
            assert_eq!(torii_request_error_is_transient(&nested), expected);
        }
        let raw_timeout = Report::from(std::io::Error::new(
            ErrorKind::TimedOut,
            "operation timed out while applying local validation",
        ));
        assert!(!torii_request_error_is_transient(&raw_timeout));
    }
    #[test]
    fn torii_request_error_is_transient_detects_query_timeout() {
        let report = eyre!(
            "Failed to send http POST request to http://127.0.0.1:47173/v1/query\n\nCaused by:\n   0: error sending request for url\n   1: operation timed out"
        );
        assert!(torii_request_error_is_transient(&report));
    }
    #[test]
    fn torii_request_error_is_transient_detects_connection_reset_transport() {
        let report = eyre!(
            "Failed to send http POST request to http://127.0.0.1:47173/v1/query\n\nCaused by:\n   0: error sending request for url\n   1: connection reset"
        );
        assert!(torii_request_error_is_transient(&report));
    }
    #[test]
    fn torii_request_error_is_transient_detects_connect_error_phrase() {
        let report = eyre!(
            "Failed to send http POST request to http://127.0.0.1:47173/v1/query\n\nCaused by:\n   0: client error (Connect)\n   1: Connection refused"
        );
        assert!(torii_request_error_is_transient(&report));
    }
    #[test]
    fn torii_request_error_is_transient_detects_raw_connection_refused_io_error() {
        let report = Report::from(std::io::Error::new(
            ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        assert!(torii_request_error_is_transient(&report));
    }
    #[test]
    fn torii_request_error_is_transient_requires_http_transport_context() {
        let report = eyre!("connection reset while applying local validation");
        assert!(!torii_request_error_is_transient(&report));
    }
    #[test]
    fn torii_request_error_is_transient_ignores_plain_timeout_without_http_context() {
        let report = eyre!("operation timed out while applying local validation");
        assert!(!torii_request_error_is_transient(&report));
    }
    #[test]
    fn torii_request_error_is_transient_ignores_http_context_without_transport_failure() {
        let report = eyre!(
            "Failed to send http POST request to http://127.0.0.1:47173/v1/query\n\nCaused by:\n   0: validation rejected duplicate domain"
        );
        assert!(!torii_request_error_is_transient(&report));
    }
    #[test]
    fn torii_request_error_is_transient_ignores_backpressure_phrase_without_status() {
        let report = eyre!(
            "Failed to send http POST request to http://127.0.0.1:47173/v1/query\n\nCaused by:\n   0: Reached the limit of parallel queries"
        );
        assert!(!torii_request_error_is_transient(&report));
    }
    #[test]
    fn torii_request_error_is_transient_ignores_validation_errors() {
        let report = eyre!("Validation failed: domain already exists");
        assert!(!torii_request_error_is_transient(&report));
    }
    #[test]
    fn peer_client_ignores_ambient_identity_and_endpoint_overrides() {
        let _guard = lock_env_guard(&CONFIG_ENV_GUARD);
        let dir = tempdir().expect("peer client fixture directory");
        let environment = Environment {
            dir: dir.path().to_path_buf(),
        };
        let peer = NetworkPeer::builder().build(&environment);
        let network_id = NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                CryptoHash::prehashed([0xA5; CryptoHash::LENGTH]),
            ),
        );
        assert!(
            peer.client_config
                .set(PeerClientConfig {
                    chain: config::chain_id(),
                    network_id,
                    chain_discriminant: defaults::common::chain_discriminant(),
                    policy: PeerClientPolicy::from_env(),
                })
                .is_ok()
        );
        let _overrides = [
            EnvVarRestore::set("CHAIN", "foreign-client-chain"),
            EnvVarRestore::set("NETWORK_ID", "invalid-ambient-network"),
            EnvVarRestore::set("TORII_URL", "http://127.0.0.1:1"),
            EnvVarRestore::set("ACCOUNT_PUBLIC_KEY", "invalid-ambient-public-key"),
            EnvVarRestore::set("ACCOUNT_PRIVATE_KEY", "invalid-ambient-private-key"),
            EnvVarRestore::set("ACCOUNT_PRIVATE_KEY_FILE", "nonexistent-ambient-key-file"),
            EnvVarRestore::set("ACCOUNT_PROFILE", "unknown-ambient-profile"),
            EnvVarRestore::set("ACCOUNT_CHAIN_DISCRIMINANT", "777"),
        ];
        let client = peer.client();
        assert_eq!(client.client().chain(), &config::chain_id());
        assert_eq!(
            client.client().account_chain_discriminant(),
            defaults::common::chain_discriminant(),
        );
        assert_eq!(client.client().network_id(), &network_id);
        assert_eq!(client.client().account(), &*ALICE_ID);
        assert_eq!(
            client.client().key_pair().public_key(),
            ALICE_KEYPAIR.public_key()
        );
        assert_eq!(
            client.client().endpoint().as_str(),
            format!("http://127.0.0.1:{}/", peer.port_api)
        );
    }
    #[test]
    fn client_status_timeout_defaults_are_generous() {
        let _guard = lock_env_guard(&CLIENT_ENV_GUARD);
        let _secs_guard = EnvVarGuard::cleared("IROHA_TEST_CLIENT_STATUS_TIMEOUT_SECS");
        let _ms_guard = EnvVarGuard::cleared("IROHA_TEST_CLIENT_STATUS_TIMEOUT_MS");
        assert_eq!(
            client_status_timeout_env(),
            CLIENT_STATUS_TIMEOUT_DEFAULT,
            "default client status timeout should tolerate slow integration runs",
        );
    }
    #[test]
    fn client_request_timeout_defaults_match_client_config_default() {
        let _guard = lock_env_guard(&CLIENT_ENV_GUARD);
        let _secs_guard = EnvVarGuard::cleared("IROHA_TEST_CLIENT_REQUEST_TIMEOUT_SECS");
        let _ms_guard = EnvVarGuard::cleared("IROHA_TEST_CLIENT_REQUEST_TIMEOUT_MS");
        assert_eq!(
            client_request_timeout_env(),
            iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            "test-network clients should inherit the same routed request budget as normal clients",
        );
    }
    #[test]
    fn client_ttl_exceeds_status_timeout_by_default() {
        let _guard = lock_env_guard(&CLIENT_ENV_GUARD);
        let _status_secs_guard = EnvVarGuard::cleared("IROHA_TEST_CLIENT_STATUS_TIMEOUT_SECS");
        let _status_ms_guard = EnvVarGuard::cleared("IROHA_TEST_CLIENT_STATUS_TIMEOUT_MS");
        let _ttl_secs_guard = EnvVarGuard::cleared("IROHA_TEST_CLIENT_TTL_SECS");
        let _ttl_ms_guard = EnvVarGuard::cleared("IROHA_TEST_CLIENT_TTL_MS");
        let status_timeout = client_status_timeout_env();
        let ttl = client_ttl_env(status_timeout);
        assert_eq!(
            ttl, CLIENT_TTL_DEFAULT,
            "default TTL should stay above the status timeout cushion"
        );
    }
    #[tokio::test]
    async fn shutdown_resets_running_flag_even_if_monitor_is_absent() {
        if skip_network_tests("shutdown_resets_running_flag_even_if_monitor_is_absent") {
            return;
        }
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
        let tasks = tokio::task::JoinSet::new();
        let (fatal_tx, mut fatal_rx) = watch::channel(false);
        {
            let mut guard = peer.run.lock().await;
            *guard = Some(PeerRun {
                tasks,
                shutdown: shutdown_tx,
                fatal_tx: fatal_tx.clone(),
                pid: None,
                #[cfg(unix)]
                broker_child: None,
            });
        }
        peer.is_running.store(true, Ordering::Relaxed);
        let notify_wait = fatal_rx.changed();
        tokio::pin!(notify_wait);
        peer.shutdown().await;
        assert!(!peer.is_running());
        assert!(peer.run.lock().await.is_none());
        tokio::time::timeout(Duration::from_secs(1), &mut notify_wait)
            .await
            .expect("shutdown should notify fatal listeners")
            .expect("fatal signal should be delivered");
    }
    #[tokio::test]
    async fn process_id_reports_only_the_current_live_run_slot() {
        if skip_network_tests("process_id_reports_only_the_current_live_run_slot") {
            return;
        }
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        assert_eq!(peer.process_id().await, None);
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
        let tasks = tokio::task::JoinSet::new();
        let (fatal_tx, _fatal_rx) = watch::channel(false);
        {
            let mut guard = peer.run.lock().await;
            *guard = Some(PeerRun {
                tasks,
                shutdown: shutdown_tx,
                fatal_tx,
                pid: Some(42_424),
                #[cfg(unix)]
                broker_child: None,
            });
        }
        assert_eq!(peer.process_id().await, Some(42_424));
        peer.run.lock().await.take();
        assert_eq!(peer.process_id().await, None);
    }
    #[tokio::test]
    async fn shutdown_if_started_returns_false_when_peer_is_not_running() {
        if skip_network_tests("shutdown_if_started_returns_false_when_peer_is_not_running") {
            return;
        }
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        assert!(
            !peer.shutdown_if_started().await,
            "shutdown_if_started should be a no-op when the peer never started"
        );
    }
    #[tokio::test]
    async fn network_drop_cleanup_tolerates_peer_that_already_stopped() {
        if skip_network_tests("network_drop_cleanup_tolerates_peer_that_already_stopped") {
            return;
        }
        let env = Environment::new();
        let running_peer = NetworkPeer::builder().build(&env);
        let stopped_peer = NetworkPeer::builder().build(&env);
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
        let tasks = tokio::task::JoinSet::new();
        let (fatal_tx, _fatal_rx) = watch::channel(false);
        {
            let mut guard = running_peer.run.lock().await;
            *guard = Some(PeerRun {
                tasks,
                shutdown: shutdown_tx,
                fatal_tx,
                pid: None,
                #[cfg(unix)]
                broker_child: None,
            });
        }
        running_peer.is_running.store(true, Ordering::Relaxed);
        shutdown_peers_for_drop(vec![running_peer.clone(), stopped_peer.clone()]).await;
        assert!(!running_peer.is_running());
        assert!(running_peer.run.lock().await.is_none());
        assert!(!stopped_peer.is_running());
        assert!(stopped_peer.run.lock().await.is_none());
    }
    #[tokio::test]
    async fn network_shutdown_clears_stale_peer_runs_even_when_not_marked_running() {
        if skip_network_tests(
            "network_shutdown_clears_stale_peer_runs_even_when_not_marked_running",
        ) {
            return;
        }
        let network = NetworkBuilder::new().build();
        let peer = network
            .peers()
            .first()
            .expect("network builder creates at least one peer")
            .clone();
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
        let tasks = tokio::task::JoinSet::new();
        let (fatal_tx, _fatal_rx) = watch::channel(false);
        {
            let mut guard = peer.run.lock().await;
            *guard = Some(PeerRun {
                tasks,
                shutdown: shutdown_tx,
                fatal_tx,
                pid: None,
                #[cfg(unix)]
                broker_child: None,
            });
        }
        peer.is_running.store(false, Ordering::Relaxed);
        network.shutdown().await;
        assert!(
            peer.run.lock().await.is_none(),
            "network shutdown should clear stale peer run handles"
        );
    }
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.original.as_ref() {
                set_env_var(self.key, value);
            } else {
                remove_env_var(self.key);
            }
        }
    }
    #[test]
    fn ordinary_load_peers_keep_exact_signed_genesis_identity_without_publisher_custody()
    -> Result<()> {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let genesis = network.genesis();
        let original_hash = genesis.0.hash();
        let original_network = NetworkId::from_genesis_hash(original_hash);
        let mut signatures = genesis.0.signatures();
        let signature = signatures.next().expect("canonical genesis signature");
        assert!(signatures.next().is_none());
        assert!(
            signature
                .signature()
                .verify_hash(network.genesis_key_pair.public_key(), original_hash,)
                .is_ok()
        );
        assert_eq!(network.network_id(), original_network);
        assert_eq!(network.validators().len(), 4);
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        for peer in network.all_peers() {
            assert!(
                peer.base_config_table()
                    .get("kagemusha_load_authorizer")
                    .is_none()
            );
            assert!(!peer.dir.join("kagemusha-load-authorizer").exists());
            let actual = resolve_actual_config_result(peer, &layers)?;
            assert_eq!(actual.genesis.expected_hash, original_hash);
            assert_eq!(actual.common.chain, network.chain_id());
            assert_eq!(
                peer.client_config.get().unwrap().network_id,
                original_network
            );
            assert_eq!(*peer.client().client().network_id(), original_network);
            let cloned = peer.clone();
            assert!(Arc::ptr_eq(&cloned.client_config, &peer.client_config));
            assert_eq!(
                resolve_actual_config_result(&cloned, &layers)?
                    .genesis
                    .expected_hash,
                original_hash,
            );
        }
        assert_eq!(network.genesis().0.hash(), original_hash);
        Ok(())
    }

    #[test]
    fn generated_peer_base_config_parses_without_retired_load_publisher() -> Result<()> {
        let dir = tempdir()?;
        let environment = Environment {
            dir: dir.path().to_path_buf(),
        };
        let peer = NetworkPeer::builder().build(&environment);
        let original = fs::read(peer.dir.join("config.base.toml"))?;
        let written: Table = toml::from_str(std::str::from_utf8(&original)?)?;
        assert!(!written.contains_key("kagemusha_load_authorizer"));
        let base = peer.base_config_table();
        assert!(!base.contains_key("kagemusha_load_authorizer"));
        let actual = resolve_actual_config_result(&peer, &[config::base_iroha_config()])?;
        assert_eq!(
            actual.common.key_pair.public_key(),
            peer.key_pair.public_key()
        );
        assert!(peer.client_config.get().is_none());
        assert!(!peer.dir.join("kagemusha-load-authorizer").exists());
        let cloned = peer.clone();
        assert_eq!(cloned.base_config_table(), base);
        assert_eq!(fs::read(peer.dir.join("config.base.toml"))?, original);
        Ok(())
    }

    #[test]
    fn ordinary_load_peer_configuration_rejects_retired_publisher_overrides() -> Result<()> {
        let dir = tempdir()?;
        let environment = Environment {
            dir: dir.path().to_path_buf(),
        };
        let peer = NetworkPeer::builder().build(&environment);
        let base = config::base_iroha_config();
        resolve_actual_config_result(&peer, std::slice::from_ref(&base))?;
        assert!(
            peer.base_config_table()
                .get("kagemusha_load_authorizer")
                .is_none()
        );
        let missing = dir.path().join("missing-caller-keyring.nrt");
        for publisher in [
            Value::Boolean(false),
            Value::Table(Table::new()),
            Value::Table(Table::from_iter([
                (
                    "keyring_file".into(),
                    missing.to_string_lossy().into_owned().into(),
                ),
                ("submitter_key_file".into(), "missing-submitter.key".into()),
            ])),
        ] {
            let mut layer = base.clone();
            layer.insert("kagemusha_load_authorizer".into(), publisher);
            let error = resolve_actual_config_result(&peer, &[layer]).expect_err(
                "retired publisher configuration must not select or synthesize custody",
            );
            assert!(
                format!("{error:#}").contains("kagemusha_load_authorizer"),
                "unexpected error: {error:?}"
            );
            assert!(!missing.exists());
            assert!(!peer.dir.join("kagemusha-load-authorizer").exists());
        }
        resolve_actual_config_result(&peer, &[base])?;
        Ok(())
    }

    #[test]
    fn write_base_config_uses_addr_literals() {
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        peer.write_base_config();
        let base_path = peer.dir.join("config.base.toml");
        let contents = fs::read_to_string(&base_path).expect("read base config");
        let parsed: TomlValue = toml::from_str(&contents).expect("parse config.toml");
        let network = parsed
            .get("network")
            .and_then(TomlValue::as_table)
            .expect("network table exists");
        let torii = parsed
            .get("torii")
            .and_then(TomlValue::as_table)
            .expect("torii table exists");
        for key in ["address", "public_address"] {
            let value = network
                .get(key)
                .and_then(TomlValue::as_str)
                .unwrap_or_else(|| panic!("{key} missing"));
            assert!(
                value.starts_with("addr:"),
                "{key} should be addr literal, got {value}"
            );
            let body = norito::literal::parse("addr", value).expect("parse addr literal");
            let port_p2p: u16 = **peer.port_p2p;
            assert!(
                body.ends_with(&port_p2p.to_string()),
                "{key} literal body should contain peer port"
            );
        }
        let torii_addr = torii
            .get("address")
            .and_then(TomlValue::as_str)
            .expect("torii.address present");
        assert!(
            torii_addr.starts_with("addr:"),
            "torii.address should be addr literal, got {torii_addr}"
        );
        let torii_body =
            norito::literal::parse("addr", torii_addr).expect("parse torii addr literal");
        let port_api: u16 = **peer.port_api;
        assert!(
            torii_body.ends_with(&port_api.to_string()),
            "torii literal body should contain API port"
        );
    }
    #[test]
    fn has_committed_block_requires_canonical_hash_journal() {
        let env = Environment::new();
        let modern_peer = NetworkPeer::builder().build(&env);
        let lane_dir = modern_peer
            .dir
            .join("storage")
            .join("blocks")
            .join("canonical");
        let pipeline_dir = lane_dir.join("pipeline");
        fs::create_dir_all(&pipeline_dir).expect("create modern pipeline dir");
        write_sidecar_index(&pipeline_dir, 1);
        assert_eq!(
            fs::metadata(pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE))
                .expect("compact sidecar index")
                .len(),
            48,
            "the regression fixture matches one compact-V1 entry plus its header"
        );
        assert!(
            !modern_peer.has_committed_block(1),
            "a pre-finality pipeline sidecar is not a commit witness"
        );
        fs::write(lane_dir.join("blocks.hashes"), vec![0u8; 32])
            .expect("write canonical hash journal");
        assert!(modern_peer.has_committed_block(1));
        assert!(!modern_peer.has_committed_block(2));
    }
    #[test]
    fn has_committed_block_uses_resolved_kura_store_dir() {
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        let custom_storage_dir = peer.dir.join("custom-storage");
        let lane_dir = custom_storage_dir.join("blocks").join("canonical");
        fs::create_dir_all(&lane_dir).expect("create custom lane dir");
        fs::write(lane_dir.join("blocks.hashes"), vec![0u8; 32])
            .expect("write custom canonical hash journal");
        {
            let mut context = peer
                .start_context
                .lock()
                .expect("startup context lock should not be poisoned");
            *context = Some(PeerStartContext {
                run_num: 1,
                config_path: peer.dir.join("run-1-config.toml"),
                genesis_path: None,
                stdout_path: peer.dir.join("run-1-stdout.log"),
                stderr_path: peer.dir.join("run-1-stderr.log"),
                kura_store_dir_key: "kura.store_dir".to_string(),
                kura_store_dir: custom_storage_dir.clone(),
                kura_store_dir_value: custom_storage_dir.display().to_string(),
            });
        }
        assert!(peer.has_committed_block(1));
        assert!(!peer.has_committed_block(2));
    }
    #[test]
    fn detect_block_height_ignores_uncommitted_lane_pipeline_index() {
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        let pipeline_dir = peer
            .dir
            .join("storage")
            .join("blocks")
            .join("canonical")
            .join("pipeline");
        fs::create_dir_all(&pipeline_dir).expect("create lane pipeline dir");
        write_sidecar_index(&pipeline_dir, 3);
        assert!(
            detect_block_height_from_storage(&peer.dir.join("storage"), 0).is_none(),
            "pipeline recovery progress must not satisfy applied-height readiness"
        );
    }
    #[test]
    fn detect_block_height_prefers_block_hashes_over_pipeline() {
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        let lane_dir = peer.dir.join("storage").join("blocks").join("canonical");
        let pipeline_dir = lane_dir.join("pipeline");
        fs::create_dir_all(&pipeline_dir).expect("create lane pipeline dir");
        write_sidecar_index(&pipeline_dir, 3);
        fs::write(lane_dir.join("blocks.hashes"), vec![0u8; 32]).expect("write blocks hash file");
        let height =
            detect_block_height_from_storage(&peer.dir.join("storage"), 0).expect("detect height");
        assert_eq!(height.total, 1);
        assert_eq!(height.non_empty, 1);
    }
    #[test]
    fn detect_block_height_never_uses_lane_alias_hash_journals() {
        let directory = tempdir().expect("storage fixture");
        let alias = directory.path().join("blocks/lane_000_default");
        fs::create_dir_all(&alias).unwrap();
        fs::write(alias.join("blocks.hashes"), vec![0u8; 32 * 20]).unwrap();
        assert!(detect_block_height_from_storage(directory.path(), 0).is_none());
        let canonical = iroha_core::kura::Kura::canonical_storage_path(directory.path());
        fs::create_dir_all(&canonical).unwrap();
        fs::write(canonical.join("blocks.hashes"), vec![0u8; 32 * 2]).unwrap();
        assert_eq!(
            detect_block_height_from_storage(directory.path(), 0)
                .expect("canonical durable height")
                .total,
            2
        );
        assert!(detect_block_height_from_storage(directory.path(), 2).is_none());
    }
    #[test]
    fn detect_block_height_rejects_partial_canonical_hash_journal() {
        let directory = tempdir().expect("storage fixture");
        let canonical = iroha_core::kura::Kura::canonical_storage_path(directory.path());
        fs::create_dir_all(&canonical).unwrap();
        fs::write(canonical.join("blocks.hashes"), vec![0u8; 33]).unwrap();
        assert!(detect_block_height_from_storage(directory.path(), 0).is_none());
        fs::remove_file(canonical.join("blocks.hashes")).unwrap();
        fs::create_dir(canonical.join("blocks.hashes")).unwrap();
        assert!(detect_block_height_from_storage(directory.path(), 0).is_none());
    }
    #[test]
    fn best_effort_block_height_uses_storage_without_status() {
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        let lane_dir = peer.dir.join("storage").join("blocks").join("canonical");
        fs::create_dir_all(&lane_dir).expect("create lane dir");
        fs::write(lane_dir.join("blocks.hashes"), vec![0u8; 64])
            .expect("write canonical hash journal");
        let height = peer.best_effort_block_height().expect("best-effort height");
        assert_eq!(height.total, 2);
        assert_eq!(height.non_empty, 2);
    }
    #[test]
    fn last_known_peers_reflects_recorded_status() {
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        let status = Status {
            peers: 5,
            blocks: 1,
            blocks_non_empty: 1,
            ..Status::default()
        };
        let _ = NetworkPeer::record_probe_status(&peer.startup_probe, &status);
        assert_eq!(peer.last_known_peers(), Some(5));
    }
    #[cfg(test)]
    fn write_sidecar_index(pipeline_dir: &Path, entries: u64) {
        const COMPACT_V1_INTEGRITY_MASK: u64 = 0x6B75_7261_2D69_6478;
        let base_height = 1_u64;
        let mut index_bytes = Vec::new();
        // Compact V1 header: sentinel, followed by base height and its
        // integrity word. This exact 32-byte prefix was previously mistaken
        // for two additional block entries by the test-network readiness path.
        index_bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        index_bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        index_bytes.extend_from_slice(&base_height.to_le_bytes());
        index_bytes.extend_from_slice(&(base_height ^ COMPACT_V1_INTEGRITY_MASK).to_le_bytes());
        for i in 0..entries {
            index_bytes.extend_from_slice(&i.to_le_bytes());
            index_bytes.extend_from_slice(&1_u64.to_le_bytes());
        }
        fs::write(
            pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE),
            vec![0_u8; usize::try_from(entries).expect("fixture entry count fits usize")],
        )
        .expect("write sidecar data");
        fs::write(
            pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE),
            &index_bytes,
        )
        .expect("write sidecar index");
    }
    #[test]
    fn write_base_config_copies_rans_tables() {
        let env = Environment::new();
        let peer = NetworkPeer::builder().build(&env);
        peer.write_base_config();
        let tables_path = peer
            .dir
            .join("codec")
            .join("rans")
            .join("tables")
            .join("rans_seed0.toml");
        assert_eq!(
            fs::read(&tables_path).expect("read materialized rANS tables"),
            DEFAULT_RANS_TABLES
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&tables_path, fs::Permissions::from_mode(0o400))
                .expect("make existing canonical tables read-only");
        }
        peer.write_base_config();
        peer.write_base_config();
        assert_eq!(
            fs::read(&tables_path).expect("read reused canonical rANS tables"),
            DEFAULT_RANS_TABLES
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&tables_path).unwrap().permissions().mode() & 0o777,
                0o400,
                "matching read-only tables must be reused without mutation"
            );
            fs::set_permissions(&tables_path, fs::Permissions::from_mode(0o600))
                .expect("prepare divergent table fixture");
        }
        fs::write(&tables_path, b"different table bytes").expect("write divergent table fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&tables_path, fs::Permissions::from_mode(0o400))
                .expect("make divergent table fixture read-only");
        }
        peer.write_base_config();
        assert_eq!(
            fs::read(&tables_path).expect("read repaired canonical rANS tables"),
            DEFAULT_RANS_TABLES
        );
    }
    #[test]
    fn trusted_peers_use_addr_literals() {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let mut layers = network.config_layers();
        let base_layer = layers
            .next()
            .expect("base config layer present")
            .into_owned();
        let trusted_peers = base_layer
            .get("trusted_peers")
            .and_then(TomlValue::as_array)
            .expect("trusted_peers array present");
        assert!(
            !trusted_peers.is_empty(),
            "trusted_peers should contain entries"
        );
        for entry in trusted_peers {
            let peer_literal = entry
                .as_str()
                .unwrap_or_else(|| panic!("trusted_peers entry should be string"));
            let (_, addr_literal) = peer_literal
                .rsplit_once('@')
                .unwrap_or_else(|| panic!("trusted peer entry malformed: {peer_literal}"));
            assert!(
                addr_literal.starts_with("addr:"),
                "trusted peer address should be literal: {addr_literal}"
            );
            let _body =
                norito::literal::parse("addr", addr_literal).expect("parse trusted peer literal");
        }
    }
    #[test]
    fn with_min_peers_rounds_up_to_revision4_committee() {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_min_peers(2));
        assert_eq!(network.peers().len(), 4);
        let network = build_with_isolated_permit(NetworkBuilder::new().with_min_peers(5));
        assert_eq!(network.peers().len(), 7);
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_peers(7).with_min_peers(4));
        assert_eq!(network.peers().len(), 7);
    }
    #[test]
    fn revision4_committee_rounding_covers_protocol_bounds() {
        for (minimum, expected) in [
            (1, Some(4)),
            (4, Some(4)),
            (5, Some(7)),
            (7, Some(7)),
            (8, Some(10)),
            (30, Some(31)),
            (31, Some(31)),
            (32, None),
            (usize::MAX, None),
        ] {
            assert_eq!(revision4_committee_at_least(minimum), expected);
        }
        for minimum in [0, MAX_VALIDATORS_PER_HEIGHT + 1, usize::MAX] {
            assert!(
                std::panic::catch_unwind(|| NetworkBuilder::new().with_min_peers(minimum)).is_err(),
                "invalid minimum {minimum} must panic before construction"
            );
        }
    }
    #[test]
    fn with_peers_rejects_non_revision4_validator_counts() {
        for peers in [0, 1, 2, 3, 5, 6, 8, 30, 32, usize::MAX] {
            assert!(
                std::panic::catch_unwind(|| NetworkBuilder::new().with_peers(peers)).is_err(),
                "invalid {peers}-peer validator committee must panic before construction"
            );
        }
    }
    #[test]
    fn max_validator_capacity_rejects_invalid_bounds_and_builder_ordering() {
        for max_validator_capacity in [
            MIN_VALIDATORS_PER_HEIGHT - 1,
            MAX_VALIDATORS_PER_HEIGHT + 1,
            usize::MAX,
        ] {
            assert!(
                std::panic::catch_unwind(|| {
                    NetworkBuilder::new().with_max_validator_capacity(max_validator_capacity)
                })
                .is_err(),
                "invalid maximum validator capacity {max_validator_capacity} must panic"
            );
        }
        assert!(
            std::panic::catch_unwind(|| {
                NetworkBuilder::new()
                    .with_max_validator_capacity(5)
                    .with_peers(7)
            })
            .is_err(),
            "raising the bootstrap roster above its earlier reservation must panic"
        );
    }
    #[test]
    fn signed_genesis_roster_must_match_guarded_network_topology() {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let genesis = network.genesis();
        let expected = network
            .peers()
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        assert_genesis_voting_roster_matches_network(&genesis, &expected);
        let incomplete = expected[..expected.len() - 1].to_vec();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_genesis_voting_roster_matches_network(&genesis, &incomplete);
            }))
            .is_err(),
            "a custom signed roster that differs from the guarded topology must fail closed"
        );
    }
    #[test]
    fn network_builder_defaults_to_four_peers() {
        let network = build_with_isolated_permit(NetworkBuilder::new());
        assert_eq!(network.peers().len(), DEFAULT_NETWORK_PEERS);
    }
    #[test]
    fn enables_norito_rpc_ga_stage_for_test_networks() {
        let network = build_with_isolated_permit(NetworkBuilder::new());
        let base_layer = network
            .config_layers()
            .find(|layer| {
                layer
                    .as_ref()
                    .get("torii")
                    .and_then(TomlValue::as_table)
                    .and_then(|torii| torii.get("transport"))
                    .is_some()
            })
            .expect("base config layer present")
            .into_owned();
        let torii_table = base_layer
            .get("torii")
            .and_then(TomlValue::as_table)
            .expect("torii table present");
        let transport_table = torii_table
            .get("transport")
            .and_then(TomlValue::as_table)
            .expect("torii.transport table present");
        let norito_rpc_table = transport_table
            .get("norito_rpc")
            .and_then(TomlValue::as_table)
            .expect("torii.transport.norito_rpc table present");
        let stage = norito_rpc_table
            .get("stage")
            .and_then(TomlValue::as_str)
            .expect("stage should be present");
        assert_eq!(
            stage, "ga",
            "default NetworkBuilder must enable GA Norito-RPC for tests"
        );
        let enabled = norito_rpc_table
            .get("enabled")
            .and_then(TomlValue::as_bool)
            .unwrap_or(false);
        assert!(
            enabled,
            "Norito-RPC must stay enabled for auto-built test networks"
        );
    }
    include!("lib/build_resolution_tests.rs");
    #[test]
    fn env_filter_defaults_to_warn() {
        let _guard = lock_env_guard(&LOG_ENV_GUARD);
        let original = env::var("RUST_LOG").ok();
        remove_env_var("RUST_LOG");
        let filter = env_filter_from_env_or_default();
        if let Some(value) = original {
            set_env_var("RUST_LOG", value);
        } else {
            remove_env_var("RUST_LOG");
        }
        assert_eq!(filter.to_string(), "warn");
    }
    #[test]
    fn env_filter_honors_rust_log_override() {
        let _guard = lock_env_guard(&LOG_ENV_GUARD);
        let original = env::var("RUST_LOG").ok();
        set_env_var("RUST_LOG", "warn");
        let filter = env_filter_from_env_or_default();
        if let Some(value) = original {
            set_env_var("RUST_LOG", value);
        } else {
            remove_env_var("RUST_LOG");
        }
        assert_eq!(filter.to_string(), "warn");
    }
    #[test]
    fn summarize_peer_stderr_ignores_empty_input() {
        assert!(summarize_peer_stderr("").is_none());
        assert!(summarize_peer_stderr("\n\n").is_none());
    }
    #[test]
    fn summarize_peer_stderr_truncates_to_tail_lines() {
        let input = (0..100)
            .map(|idx| format!("line {idx}"))
            .collect::<Vec<_>>()
            .join("\n");
        let summary = summarize_peer_stderr(&input).expect("summary should exist");
        assert!(summary.truncated);
        assert_eq!(summary.total_lines, 100);
        assert!(summary.preview.lines().count() <= PEER_STDERR_PREVIEW_MAX_LINES);
        assert!(summary.preview.ends_with("line 99"));
    }
    #[test]
    fn summarize_peer_stderr_limits_character_count() {
        let long_line = "x".repeat(PEER_STDERR_PREVIEW_MAX_CHARS + 10);
        let input = format!("first\n{long_line}");
        let summary = summarize_peer_stderr(&input).expect("summary should exist");
        assert!(summary.truncated);
        assert_eq!(summary.total_lines, 2);
        assert!(summary.preview.len() <= PEER_STDERR_PREVIEW_MAX_CHARS);
        assert!(summary.preview.ends_with('x'));
    }
    #[test]
    fn summarize_peer_stdout_file_retains_bounded_failure_tail() {
        let directory = tempfile::tempdir().expect("temporary peer log directory");
        let path = directory.path().join("run-1-stdout.log");
        let mut input = (0..10_000)
            .map(|index| format!("ordinary startup line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        input.push_str("\nSumeragi effect services failed closed: exact ownership violation\n");
        for index in 0..100 {
            input.push_str(&format!("ordinary shutdown detail {index}\n"));
        }
        fs::write(&path, input).expect("write synthetic peer stdout");
        let summary = summarize_peer_stdout_file(&path).expect("stdout summary should exist");
        assert!(summary.truncated);
        assert!(summary.preview.len() <= PEER_STDERR_PREVIEW_MAX_CHARS);
        assert!(
            summary
                .preview
                .contains("Sumeragi effect services failed closed: exact ownership violation")
        );
        assert!(summary.preview.contains("... decisive peer failure ..."));
    }
    #[test]
    fn canonical_genesis_bytes_roundtrip_signed_block() {
        init_instruction_registry();
        let network = NetworkBuilder::new().build();
        let genesis = network.genesis();
        println!(
            "GENESIS contains {} transactions",
            network.genesis_isi().len()
        );
        for (tx_idx, tx) in network.genesis_isi().iter().enumerate() {
            println!("GENESIS tx {tx_idx} has {} instructions", tx.len());
            for (instr_idx, instr) in tx.iter().enumerate() {
                let type_name = Instruction::id(&**instr);
                println!("GENESIS instruction tx {tx_idx} idx {instr_idx}: {type_name}");
                let encoded = norito::to_bytes(instr).expect("encode genesis instruction");
                norito::from_bytes::<iroha_data_model::isi::InstructionBox>(&encoded)
                    .unwrap_or_else(|error| {
                        panic!(
                            "genesis instruction decode failed at tx #{tx_idx} instr #{instr_idx}: {error}"
                        )
                    });
            }
        }
        let wire =
            NetworkPeer::canonical_genesis_bytes(&genesis).expect("canonical genesis encoding");
        println!(
            "canonical wire header_flags_byte=0x{:02x}",
            wire[1 + norito::core::Header::SIZE - 1]
        );
        println!("wire prefix {:?}", &wire[..32.min(wire.len())]);
        let header_size = norito::core::Header::SIZE;
        println!(
            "payload prefix {:?}",
            &wire[header_size..(header_size + 32).min(wire.len())]
        );
        decode_framed_signed_block(&wire).expect("decode framed genesis block");
    }
    fn collect_set_parameters(block: &GenesisBlock) -> Vec<Parameter> {
        block
            .0
            .external_transactions()
            .flat_map(|tx| match tx.instructions() {
                Executable::Instructions(instructions) => instructions
                    .iter()
                    .filter_map(|instruction| {
                        instruction
                            .as_any()
                            .downcast_ref::<SetParameter>()
                            .map(|set| set.inner().clone())
                    })
                    .collect::<Vec<_>>(),
                Executable::Batch(items) => items
                    .iter()
                    .filter_map(|item| match item {
                        ExecutableBatchItem::Instruction(instruction) => instruction
                            .as_any()
                            .downcast_ref::<SetParameter>()
                            .map(|set| set.inner().clone()),
                        ExecutableBatchItem::ContractCall(_) => None,
                    })
                    .collect(),
                Executable::ContractCall(_) => Vec::new(),
                Executable::Ivm(_) => Vec::new(),
                Executable::IvmProved(_) => Vec::new(),
            })
            .collect()
    }
    fn consensus_fingerprint_from_block(block: &GenesisBlock) -> Option<String> {
        consensus_handshake_metadata(block)
            .map(|metadata| metadata.consensus_fingerprint.to_string())
    }
    fn consensus_handshake_metadata(block: &GenesisBlock) -> Option<ConsensusHandshakeMetadata> {
        let mut last = None;
        for parameter in collect_set_parameters(block) {
            if let Parameter::Custom(custom) = parameter
                && custom.id() == &consensus_metadata::handshake_meta_id()
                && let Ok(metadata) = norito::json::from_str(custom.payload().get())
            {
                last = Some(metadata);
            }
        }
        last
    }
    fn assert_exactly_one_consensus_handshake(block: &GenesisBlock, expected: &Parameter) {
        let handshakes = collect_set_parameters(block)
            .into_iter()
            .filter(|parameter| {
                matches!(
                    parameter,
                    Parameter::Custom(custom)
                        if custom.id() == &consensus_metadata::handshake_meta_id()
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            handshakes,
            vec![expected.clone()],
            "genesis must contain exactly one handshake metadata entry equal to the runtime profile"
        );
    }
    fn collect_non_parameter_instructions(block: &GenesisBlock) -> Vec<InstructionBox> {
        block
            .0
            .external_transactions()
            .flat_map(|transaction| match transaction.instructions() {
                Executable::Instructions(instructions) => instructions
                    .iter()
                    .filter(|instruction| !instruction.as_any().is::<SetParameter>())
                    .cloned()
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect()
    }
    fn reconstructed_consensus_params(block: &GenesisBlock) -> ConsensusGenesisParams {
        let mut state = iroha_data_model::parameter::Parameters::default();
        for parameter in collect_set_parameters(block) {
            state.set_parameter(parameter);
        }
        let metadata = consensus_handshake_metadata(block)
            .expect("genesis must contain canonical consensus metadata");
        state.sumeragi.block_cadence_ms = metadata.block_cadence_ms;
        let mode = match metadata.mode {
            SumeragiConsensusMode::Permissioned => ConsensusMode::Permissioned,
            SumeragiConsensusMode::Npos => ConsensusMode::Npos,
        };
        iroha_core::sumeragi::consensus::consensus_genesis_params_from_parameters(
            mode,
            &state,
            metadata.sumeragi_context,
        )
        .expect("genesis must reconstruct one canonical consensus carrier")
    }
    fn assert_signed_nexus_amx_context_matches_preexecution(
        network: &Network,
        genesis: &GenesisBlock,
    ) {
        let config_layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let actual = resolve_actual_config(
            network
                .peers
                .first()
                .expect("test network must contain a peer"),
            &config_layers,
        )
        .expect("test-network peer config must resolve for genesis staging");
        let topology = network
            .peers
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        let staged = config::staged_genesis_policy_hashes(
            genesis,
            &AccountId::new(network.genesis_key_pair.public_key().clone()),
            &topology,
            &network.genesis_key_pair,
            Some(&actual.pipeline),
            Some(&actual.nexus),
            Some(&actual.zk),
            Some(&actual),
        )
        .expect("signed genesis must independently pre-execute");
        let metadata = consensus_handshake_metadata(genesis)
            .expect("genesis must contain canonical consensus metadata");
        assert_eq!(
            staged.nexus_amx,
            CryptoHash::prehashed(metadata.sumeragi_context.nexus_amx_context_hash),
            "signed Nexus/AMX commitment must equal the independently staged projection"
        );
        assert_eq!(
            staged.execution_policy,
            CryptoHash::prehashed(metadata.sumeragi_context.execution_policy_hash),
            "signed execution-policy commitment must equal the independently staged projection"
        );
    }
    #[test]
    fn genesis_consensus_metadata_matches_runtime_profile() {
        init_instruction_registry();
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let genesis = network.genesis();
        assert_signed_nexus_amx_context_matches_preexecution(&network, &genesis);
        let actual = consensus_fingerprint_from_block(&genesis)
            .expect("genesis should contain consensus fingerprint metadata");
        let profile = network.consensus_bootstrap_profile();
        assert_exactly_one_consensus_handshake(&genesis, &consensus_handshake_parameter(&profile));
        assert_eq!(
            profile.chain_id,
            network.chain_id(),
            "bootstrap profile should reuse the network chain id"
        );
        let reconstructed = reconstructed_consensus_params(&genesis);
        assert_eq!(
            reconstructed, profile.params,
            "genesis must preserve the complete canonical consensus carrier"
        );
        let expected_bytes = compute_consensus_parameters_fingerprint(&profile.params)
            .expect("profile must fingerprint");
        let expected = format!("0x{}", hex_lower(&expected_bytes));
        assert_eq!(
            actual.to_ascii_lowercase(),
            expected,
            "consensus fingerprint mismatch: expected {expected}, got {actual}"
        );
    }
    #[test]
    fn genesis_consensus_metadata_tracks_npos_mode() {
        init_instruction_registry();
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_peers(4).with_npos_consensus());
        let profile = network.consensus_bootstrap_profile();
        assert_eq!(
            profile.mode_tag, NPOS_TAG,
            "network builder should detect NPoS consensus"
        );
        assert_eq!(
            profile.bls_domain, NPOS_BLS_DOMAIN,
            "NPoS handshake must use the NPoS BLS domain"
        );
        let ConsensusGenesisModeParams::Npos(ref npos) = profile.params.mode else {
            panic!("NPoS profile must embed NPoS genesis parameters")
        };
        assert_eq!(
            npos.epoch_length_blocks.get(),
            defaults::sumeragi::npos::EPOCH_LENGTH_BLOCKS,
            "epoch length should follow config defaults when unspecified"
        );
        let genesis = network.genesis();
        assert_signed_nexus_amx_context_matches_preexecution(&network, &genesis);
        assert_exactly_one_consensus_handshake(&genesis, &consensus_handshake_parameter(&profile));
        let metadata = consensus_handshake_metadata(&genesis)
            .expect("genesis should encode consensus handshake metadata");
        assert_eq!(
            metadata.mode,
            SumeragiConsensusMode::Npos,
            "handshake metadata should advertise NPoS mode"
        );
        assert_eq!(
            metadata.sumeragi_context, profile.params.sumeragi_context,
            "handshake metadata should carry the exact signed Sumeragi context"
        );
        let actual = consensus_fingerprint_from_block(&genesis)
            .expect("genesis should contain consensus fingerprint")
            .to_ascii_lowercase();
        let expected_bytes = compute_consensus_parameters_fingerprint(&profile.params)
            .expect("NPoS profile must fingerprint");
        let expected = format!("0x{}", hex_lower(&expected_bytes));
        assert_eq!(
            actual, expected,
            "NPoS fingerprint must match runtime profile"
        );
    }
    #[test]
    fn genesis_consensus_metadata_matches_shared_runtime_derivation_for_npos() {
        init_instruction_registry();
        let mut npos = SumeragiNposParameters::default();
        npos.max_validators = 4;
        npos.epoch_length_blocks = std::num::NonZeroU64::new(3_600).unwrap();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_block_cadence(Duration::from_millis(666))
                .with_genesis_instruction(SetParameter::new(Parameter::Block(
                    iroha_data_model::parameter::BlockParameter::MaxTransactions(
                        std::num::NonZeroU64::new(512).expect("non-zero block size"),
                    ),
                )))
                .with_npos_consensus()
                .with_genesis_instruction(SetParameter::new(Parameter::Custom(
                    npos.into_custom_parameter(),
                ))),
        );
        let config_layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let actual = resolve_final_actual_config(&network.peers()[0], &config_layers);
        assert_eq!(
            actual.common.trusted_peers.value().validator_roster_len(),
            4
        );
        let genesis = network.genesis();
        let profile = network.consensus_bootstrap_profile();
        let mut parameter_state = consensus_parameters_from_genesis(&genesis);
        let metadata = consensus_handshake_metadata(&genesis)
            .expect("genesis should contain canonical consensus metadata");
        parameter_state.sumeragi.block_cadence_ms = metadata.block_cadence_ms;
        let shared_params =
            iroha_core::sumeragi::consensus::consensus_genesis_params_from_parameters(
                ConsensusMode::Npos,
                &parameter_state,
                metadata.sumeragi_context,
            )
            .expect("shared runtime derivation must accept the canonical carrier");
        assert_eq!(
            profile.params, shared_params,
            "test-network genesis metadata must use the same NPoS fingerprint inputs as runtime validation"
        );
        let actual_fingerprint = consensus_fingerprint_from_block(&genesis)
            .expect("genesis should contain consensus fingerprint")
            .to_ascii_lowercase();
        let expected = format!(
            "0x{}",
            hex_lower(
                &compute_consensus_parameters_fingerprint(&shared_params)
                    .expect("shared NPoS params must fingerprint")
            )
        );
        assert_eq!(actual_fingerprint, expected);
    }
    #[test]
    fn genesis_consensus_metadata_includes_post_topology_parameters() {
        init_instruction_registry();
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_genesis_post_topology_isi(vec![
                InstructionBox::from(SetParameter::new(Parameter::Block(
                    iroha_data_model::parameter::BlockParameter::MaxTransactions(
                        std::num::NonZeroU64::new(7_500)
                            .expect("test transaction bound must be non-zero"),
                    ),
                ))),
            ]));
        let genesis = network.genesis();
        let actual = consensus_fingerprint_from_block(&genesis)
            .expect("genesis should contain consensus fingerprint")
            .to_ascii_lowercase();
        let profile = network.consensus_bootstrap_profile();
        let expected_bytes = compute_consensus_parameters_fingerprint(&profile.params)
            .expect("profile must fingerprint");
        let expected = format!("0x{}", hex_lower(&expected_bytes));
        let reconstructed = reconstructed_consensus_params(&genesis);
        assert_eq!(
            actual, expected,
            "post-topology consensus params should affect fingerprint"
        );
        assert_eq!(
            reconstructed.block_max_transactions.get(),
            7_500,
            "post-topology block bound should be visible in final genesis consensus params"
        );
    }
    #[test]
    fn genesis_embeds_da_proof_policies_from_config_layers() {
        init_instruction_registry();
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_peers(4).with_config_layer(
                |layer| {
                    let mut lane0 = Table::new();
                    lane0.insert("index".into(), Value::Integer(0));
                    lane0.insert("alias".into(), Value::String("alpha".to_string()));
                    lane0.insert("metadata".into(), Value::Table(Table::new()));
                    let mut lane1 = Table::new();
                    lane1.insert("index".into(), Value::Integer(1));
                    lane1.insert("alias".into(), Value::String("beta".to_string()));
                    lane1.insert("metadata".into(), Value::Table(Table::new()));
                    let lane_catalog = Value::Array(vec![Value::Table(lane0), Value::Table(lane1)]);
                    layer
                        .write(["nexus", "lane_count"], 2i64)
                        .write(["nexus", "lane_catalog"], lane_catalog);
                },
            ));
        let config_layers: Vec<Table> = network.config_layers().map(Cow::into_owned).collect();
        let peer = network.peers().first().expect("network should have peers");
        let mut merged = peer.base_config_table();
        for layer in &config_layers {
            merge_tables(&mut merged, layer);
        }
        let nexus = merged
            .get("nexus")
            .and_then(Value::as_table)
            .expect("nexus table should exist");
        assert!(
            !nexus.contains_key("enabled"),
            "config must not synthesize the retired Nexus switch"
        );
        assert_eq!(
            nexus.get("lane_count").and_then(Value::as_integer),
            Some(2),
            "config should retain the overridden lane_count"
        );
        let policies = resolve_da_proof_policies(peer, &config_layers)
            .expect("should resolve da proof policies");
        assert_eq!(policies.policies().len(), 2);
        let actual = resolve_actual_config(peer, &config_layers)
            .expect("should resolve full config for genesis");
        assert_eq!(
            actual.nexus.lane_config.entries().len(),
            2,
            "resolved lane config should preserve the lane catalog"
        );
        let genesis = network.genesis();
        assert_eq!(
            genesis.0.da_proof_policies(),
            Some(&policies),
            "genesis should embed da proof policies"
        );
        assert_eq!(
            genesis.0.header().da_proof_policies_hash(),
            Some(HashOf::new(&policies))
        );
    }
    #[test]
    fn genesis_embeds_confidential_policy_hash_from_config_layers() {
        init_instruction_registry();
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_peers(4).with_config_layer(
                |layer| {
                    layer.write(["zk", "pipa_r", "enabled"], true);
                },
            ));
        let config_layers: Vec<Table> = network.config_layers().map(Cow::into_owned).collect();
        let peer = network.peers().first().expect("network should have peers");
        let actual = resolve_actual_config(peer, &config_layers)
            .expect("should resolve full config for genesis");
        let expected = iroha_core::state::compute_genesis_confidential_policy_hash(&actual.zk);
        let genesis = network.genesis();
        assert_eq!(
            genesis
                .0
                .header()
                .confidential_features()
                .and_then(|digest| digest.zk_policy_hash),
            Some(expected),
            "genesis should commit to the confidential policy resolved from config layers"
        );
    }
    #[test]
    fn config_layers_include_trusted_peer_pop_and_bls() {
        use std::collections::{BTreeMap, BTreeSet};
        fn assert_trusted_entries(network: &Network) {
            let mut layers = network.config_layers();
            let base = layers.next().expect("base config layer").into_owned();
            let mut expected_pop = BTreeMap::new();
            for peer in network.peers() {
                expected_pop.insert(
                    peer.bls_public_key()
                        .expect("trusted peer should have auto-generated BLS key")
                        .to_string(),
                    format!(
                        "0x{}",
                        hex_lower(
                            peer.bls_pop()
                                .expect("trusted peer should have auto-generated PoP")
                        )
                    ),
                );
            }
            let expected_trusted: BTreeSet<String> = network
                .peers()
                .iter()
                .map(|peer| {
                    format!(
                        "{}@{}",
                        peer.network_peer_id(),
                        peer.p2p_address().to_literal()
                    )
                })
                .collect();
            let trusted_entries = base
                .get("trusted_peers")
                .and_then(toml::Value::as_array)
                .expect("trusted_peers array");
            let actual_trusted: BTreeSet<String> = trusted_entries
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("trusted_peers entry string")
                        .to_string()
                })
                .collect();
            assert_eq!(actual_trusted, expected_trusted);
            let pop_entries = base
                .get("trusted_peers_pop")
                .and_then(toml::Value::as_array)
                .expect("trusted_peers_pop array");
            assert_eq!(pop_entries.len(), expected_pop.len());
            for entry in pop_entries {
                let table = entry.as_table().expect("pop entry table");
                let pk = table
                    .get("public_key")
                    .and_then(toml::Value::as_str)
                    .expect("pop public key");
                let pop_hex = table
                    .get("pop_hex")
                    .and_then(toml::Value::as_str)
                    .expect("pop hex");
                let expected = expected_pop.get(pk).expect("expected pop entry");
                assert_eq!(expected.as_str(), pop_hex);
            }
        }
        let default_network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        assert_trusted_entries(&default_network);
        let explicit_network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_auto_populated_trusted_peers(),
        );
        assert_trusted_entries(&explicit_network);
    }
    #[test]
    fn max_validator_capacity_reserves_four_to_five_without_expanding_bootstrap_roster() {
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_max_validator_capacity(5),
        );
        let bootstrap_layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let bootstrap = resolve_final_actual_config(&network.peers()[0], &bootstrap_layers);
        assert_eq!(
            bootstrap
                .common
                .trusted_peers
                .value()
                .validator_roster_len(),
            4,
            "capacity reservation must not manufacture bootstrap PoPs"
        );

        let extra_peer = NetworkPeerBuilder::new().build(network.env());
        let joining_layers = network
            .config_layers_with_additional_peers([&extra_peer])
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let joining = resolve_final_actual_config(&extra_peer, &joining_layers);
        assert_eq!(
            joining.common.trusted_peers.value().validator_roster_len(),
            5
        );
    }
    #[test]
    fn config_layers_with_additional_peers_include_pop() {
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_max_validator_capacity(5),
        );
        let extra_peer = NetworkPeerBuilder::new().build(network.env());
        let layers = network
            .config_layers_with_additional_peers([&extra_peer])
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let base = layers.first().expect("trusted peer config layer");
        let pop_entries = base
            .get("trusted_peers_pop")
            .and_then(toml::Value::as_array)
            .expect("trusted_peers_pop array");
        let extra_pk = extra_peer
            .bls_public_key()
            .expect("extra peer should have BLS key")
            .to_string();
        assert!(
            pop_entries.iter().any(|entry| {
                entry
                    .get("public_key")
                    .and_then(toml::Value::as_str)
                    .map(|pk| pk == extra_pk)
                    .unwrap_or(false)
            }),
            "additional peer PoP should be threaded into trusted_peers_pop"
        );
        let actual = resolve_final_actual_config(&extra_peer, &layers);
        assert_eq!(
            actual.common.trusted_peers.value().validator_roster_len(),
            5
        );
    }
    #[test]
    fn max_validator_capacity_checks_planned_full_fanout_boundary() {
        let panic = std::panic::catch_unwind(|| {
            build_with_isolated_permit(
                NetworkBuilder::new()
                    .with_peers(4)
                    .with_max_validator_capacity(5)
                    .with_base_seed(stringify!(
                        max_validator_capacity_rejects_underbudget_full_fanout
                    ))
                    .with_config_layer(|layer| {
                        layer.write(["network", "max_total_connections"], 3i64);
                    }),
            );
        })
        .expect_err("five planned validators require four connections per peer");
        let panic_message = panic
            .downcast_ref::<&str>()
            .map(std::string::ToString::to_string)
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<missing panic message>".to_owned());
        assert!(
            panic_message.contains("effective network connection capacity 3")
                && panic_message.contains("planned full-fanout minimum 4"),
            "planned fanout failure should be localized, got: {panic_message}"
        );

        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_max_validator_capacity(5)
                .with_base_seed(stringify!(max_validator_capacity_accepts_exact_full_fanout))
                .with_config_layer(|layer| {
                    layer.write(["network", "max_total_connections"], 4i64);
                }),
        );
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let actual = resolve_final_actual_config(&network.peers()[0], &layers);
        assert_eq!(effective_network_reply_source_capacity(&actual.network), 4);
    }
    #[test]
    fn max_validator_capacity_preserves_non_validator_trusted_fanout() {
        let observer =
            ObserverP2pBootstrap::new(1).expect("one non-voting trusted peer fits core capacity");
        let panic = std::panic::catch_unwind(|| {
            build_with_isolated_permit(
                NetworkBuilder::new()
                    .with_peers(4)
                    .with_observer_p2p_bootstrap(observer)
                    .expect("bootstrap observer fits core capacity")
                    .with_max_validator_capacity(5)
                    .with_base_seed(stringify!(
                        max_validator_capacity_rejects_observer_fanout_underbudget
                    ))
                    .with_config_layer(|layer| {
                        layer.write(["network", "max_total_connections"], 4i64);
                    }),
            );
        })
        .expect_err("one observer plus five planned validators require five connections per peer");
        let panic_message = panic
            .downcast_ref::<&str>()
            .map(std::string::ToString::to_string)
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<missing panic message>".to_owned());
        assert!(
            panic_message.contains("effective network connection capacity 4")
                && panic_message.contains("planned full-fanout minimum 5")
                && panic_message
                    .contains("4 current remote trusted peers plus 1 additional validators"),
            "planned observer fanout failure should be localized, got: {panic_message}"
        );

        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_observer_p2p_bootstrap(observer)
                .expect("bootstrap observer fits core capacity")
                .with_max_validator_capacity(5)
                .with_base_seed(stringify!(
                    max_validator_capacity_accepts_exact_observer_fanout
                ))
                .with_config_layer(|layer| {
                    layer.write(["network", "max_total_connections"], 5i64);
                }),
        );
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let actual = resolve_final_actual_config(&network.validators()[0], &layers);
        assert_eq!(actual.common.trusted_peers.value().others.len(), 4);
        assert_eq!(actual.common.trusted_peers.value().pops.len(), 4);
        assert_eq!(effective_network_reply_source_capacity(&actual.network), 5);
    }
    #[test]
    fn trusted_peers_layer_for_parse_includes_pop_entries() {
        let env = Environment::new();
        let peers = vec![
            NetworkPeerBuilder::new().build(&env),
            NetworkPeerBuilder::new().build(&env),
        ];
        let layer = trusted_peers_layer_for_parse(&peers, true);
        let trusted_entries = layer
            .get("trusted_peers")
            .and_then(toml::Value::as_array)
            .expect("trusted_peers array");
        assert_eq!(trusted_entries.len(), peers.len());
        let pop_entries = layer
            .get("trusted_peers_pop")
            .and_then(toml::Value::as_array)
            .expect("trusted_peers_pop array");
        assert_eq!(pop_entries.len(), peers.len());
        for peer in &peers {
            let pk = peer
                .bls_public_key()
                .expect("peer should have BLS key")
                .to_string();
            assert!(
                pop_entries.iter().any(|entry| {
                    entry
                        .get("public_key")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|value| value == pk)
                }),
                "trusted_peers_pop should include {pk}"
            );
        }
        let layer_without_pop = trusted_peers_layer_for_parse(&peers, false);
        assert!(
            layer_without_pop.get("trusted_peers_pop").is_none(),
            "trusted_peers_pop should be omitted when auto-populate is disabled"
        );
    }
    #[test]
    fn observer_bootstrap_trusts_all_participants_but_keeps_validator_only_roster() {
        let bootstrap = ObserverP2pBootstrap::new(5).expect("five observers fit the core profile");
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_base_seed(stringify!(
                    observer_bootstrap_trusts_all_participants_but_keeps_validator_only_roster
                ))
                .with_observer_p2p_bootstrap(bootstrap)
                .expect("four validators and five observers fit the P2P cap"),
        );
        assert_eq!(network.peers().len(), 4);
        assert_eq!(network.validators().len(), 4);
        assert_eq!(network.observers().len(), 5);
        assert_eq!(network.all_peers().count(), 9);
        assert_eq!(network.topology_entries().len(), 4);
        let validator_keys = network
            .validators()
            .iter()
            .map(|peer| {
                peer.bls_public_key()
                    .expect("validator has BLS identity")
                    .to_string()
            })
            .collect::<BTreeSet<_>>();
        let observer_keys = network
            .observers()
            .iter()
            .map(|peer| {
                peer.bls_public_key()
                    .expect("observer has signed BLS identity")
                    .to_string()
            })
            .collect::<BTreeSet<_>>();
        let topology_keys = network
            .topology_entries()
            .iter()
            .map(|entry| entry.peer.public_key.to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(topology_keys, validator_keys);
        assert!(topology_keys.is_disjoint(&observer_keys));
        let trusted_layer = network
            .config_layers()
            .next()
            .expect("trusted peer layer")
            .into_owned();
        let trusted = trusted_layer
            .get("trusted_peers")
            .and_then(Value::as_array)
            .expect("trusted peer array");
        assert_eq!(trusted.len(), 9);
        for peer in network.all_peers() {
            let expected = format!(
                "{}@{}",
                peer.network_peer_id(),
                peer.p2p_address().to_literal()
            );
            assert!(
                trusted
                    .iter()
                    .any(|entry| entry.as_str() == Some(&expected))
            );
        }
        let pop_keys = trusted_layer
            .get("trusted_peers_pop")
            .and_then(Value::as_array)
            .expect("validator PoP array")
            .iter()
            .map(|entry| {
                entry
                    .get("public_key")
                    .and_then(Value::as_str)
                    .expect("PoP public key")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(pop_keys, validator_keys);
        assert!(pop_keys.is_disjoint(&observer_keys));
        let resolved_layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let resolved = resolve_actual_config(&network.validators()[0], &resolved_layers)
            .expect("validator config accepts trusted observers without PoPs");
        let resolved_trusted = resolved.common.trusted_peers.value();
        assert_eq!(resolved_trusted.others.len(), 8);
        assert_eq!(resolved_trusted.pops.len(), 4);
        assert_eq!(resolved.common.trusted_peers.value().others.len(), 8);
        assert!(effective_network_reply_source_capacity(&resolved.network) >= 8);
        let role = observer_role_layer();
        assert_eq!(
            get_nested_value(&role, &["sumeragi", "role"]).and_then(Value::as_str),
            Some("observer")
        );
    }
    #[test]
    fn committee_validator_bootstrap_keeps_exact_global_roster_and_validator_role() {
        let bootstrap = CommitteeValidatorP2pBootstrap::new(5)
            .expect("five committee validators fit the core profile");
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_base_seed(stringify!(
                    committee_validator_bootstrap_keeps_exact_global_roster_and_validator_role
                ))
                .with_committee_validator_p2p_bootstrap(bootstrap)
                .expect("four global and five committee validators fit the P2P cap"),
        );
        assert_eq!(network.peers().len(), 4);
        assert_eq!(network.validators().len(), 4);
        assert_eq!(network.committee_validators().len(), 5);
        assert!(network.observers().is_empty());
        assert_eq!(network.all_peers().count(), 9);
        assert_eq!(network.topology_entries().len(), 4);

        let global_keys = network
            .validators()
            .iter()
            .map(|peer| peer.id().public_key().to_string())
            .collect::<BTreeSet<_>>();
        let committee_keys = network
            .committee_validators()
            .iter()
            .map(|peer| peer.id().public_key().to_string())
            .collect::<BTreeSet<_>>();
        let topology_keys = network
            .topology_entries()
            .iter()
            .map(|entry| entry.peer.public_key().to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(topology_keys, global_keys);
        assert!(topology_keys.is_disjoint(&committee_keys));

        let trusted_layer = network
            .config_layers()
            .next()
            .expect("trusted peer layer")
            .into_owned();
        assert_eq!(
            trusted_layer
                .get("trusted_peers")
                .and_then(Value::as_array)
                .expect("trusted peer array")
                .len(),
            9
        );
        let pop_keys = trusted_layer
            .get("trusted_peers_pop")
            .and_then(Value::as_array)
            .expect("global validator PoP array")
            .iter()
            .map(|entry| {
                entry
                    .get("public_key")
                    .and_then(Value::as_str)
                    .expect("PoP public key")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(pop_keys, global_keys);
        assert!(pop_keys.is_disjoint(&committee_keys));

        let base_layer_count = network.config_layers().count();
        for peer in network.committee_validators() {
            let layers = network.config_layers_for_peer(peer).collect::<Vec<_>>();
            assert_eq!(layers.len(), base_layer_count);
            assert!(layers.iter().all(|layer| {
                get_nested_value(layer, &["sumeragi", "role"]).and_then(Value::as_str)
                    != Some("observer")
            }));
        }
        let resolved_layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let resolved = resolve_actual_config(&network.validators()[0], &resolved_layers)
            .expect("validator config reserves supplementary committee ingress lanes");
        assert_eq!(resolved.common.trusted_peers.value().others.len(), 8);
        assert!(effective_network_reply_source_capacity(&resolved.network) >= 8);
    }
    #[test]
    fn committee_validator_bootstrap_rejects_an_underbudget_connection_override() {
        let preexecution_count = config::genesis_preexecution_count();
        let panic = std::panic::catch_unwind(|| {
            build_with_isolated_permit(
                NetworkBuilder::new()
                    .with_peers(4)
                    .with_base_seed(stringify!(
                        committee_validator_bootstrap_rejects_an_underbudget_connection_override
                    ))
                    .with_committee_validator_p2p_bootstrap(
                        CommitteeValidatorP2pBootstrap::new(5)
                            .expect("valid committee-validator count"),
                    )
                    .expect("bounded participant fanout")
                    .with_config_layer(|layer| {
                        layer.write(["network", "max_total_connections"], 7i64);
                    }),
            );
        })
        .expect_err("caller override must not erase committee ingress reservations");
        let panic_message = panic
            .downcast_ref::<&str>()
            .map(std::string::ToString::to_string)
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<missing panic message>".to_owned());
        assert!(
            panic_message.contains("trusted-peer full fanout requires 8 remote connections")
                && panic_message.contains("effective network connection capacity 7"),
            "merged configuration must report the exact required and available capacity: {panic_message}"
        );
        assert_eq!(
            config::genesis_preexecution_count(),
            preexecution_count,
            "invalid participant capacity must fail before genesis execution"
        );
    }
    #[test]
    fn mixed_committee_and_observer_bootstrap_reserves_every_non_global_source() {
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_base_seed(stringify!(
                    mixed_committee_and_observer_bootstrap_reserves_every_non_global_source
                ))
                .with_committee_validator_p2p_bootstrap(
                    CommitteeValidatorP2pBootstrap::new(3)
                        .expect("valid committee-validator count"),
                )
                .expect("bounded committee participant fanout")
                .with_observer_p2p_bootstrap(
                    ObserverP2pBootstrap::new(2).expect("valid observer count"),
                )
                .expect("bounded mixed participant fanout"),
        );
        let resolved_layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let resolved = resolve_actual_config(&network.validators()[0], &resolved_layers)
            .expect("mixed participant config resolves");
        assert_eq!(resolved.common.trusted_peers.value().others.len(), 8);
        assert!(effective_network_reply_source_capacity(&resolved.network) >= 8);
    }
    #[test]
    fn observer_bootstrap_identities_are_stable_and_shared_layers_have_no_secrets() {
        let seed =
            stringify!(observer_bootstrap_identities_are_stable_and_shared_layers_have_no_secrets);
        let recipe = NetworkBuilder::new()
            .with_peers(4)
            .with_base_seed(seed)
            .with_observer_p2p_bootstrap(
                ObserverP2pBootstrap::new(5).expect("bounded observer recipe"),
            )
            .expect("bounded participant fanout");
        let first = build_with_isolated_permit(recipe.clone());
        let first_validators = first
            .validators()
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        let first_observers = first
            .observers()
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        let serialized = first
            .config_layers()
            .map(|layer| toml::to_string(layer.as_ref()).expect("serialize shared test layer"))
            .collect::<String>();
        for peer in first.all_peers() {
            let consensus_secret = ExposedPrivateKey(
                peer.bls_key_pair()
                    .expect("participant has a BLS keypair")
                    .private_key()
                    .clone(),
            )
            .to_string();
            let streaming_secret =
                ExposedPrivateKey(peer.streaming_key_pair().private_key().clone()).to_string();
            let soranet_transport_secret =
                ExposedPrivateKey(peer.soranet_transport_key_pair().private_key().clone())
                    .to_string();
            assert!(!serialized.contains(&consensus_secret));
            assert!(!serialized.contains(&streaming_secret));
            assert!(!serialized.contains(&soranet_transport_secret));
        }
        drop(first);
        let second = build_with_isolated_permit(recipe);
        assert_eq!(
            second
                .validators()
                .iter()
                .map(NetworkPeer::id)
                .collect::<Vec<_>>(),
            first_validators
        );
        assert_eq!(
            second
                .observers()
                .iter()
                .map(NetworkPeer::id)
                .collect::<Vec<_>>(),
            first_observers
        );
        let descriptor = ObserverP2pBootstrap::new(5).expect("bounded observer recipe");
        assert_eq!(
            format!("{descriptor:?}"),
            "ObserverP2pBootstrap { observer_count: 5 }"
        );
    }
    #[test]
    fn observer_bootstrap_bounds_fail_closed() {
        assert_eq!(
            ObserverP2pBootstrap::new(0),
            Err(ObserverP2pBootstrapError::ZeroObservers)
        );
        let capacity = ObserverP2pBootstrap::connection_capacity();
        let above_capacity = capacity.checked_add(1).expect("test capacity fits usize");
        assert_eq!(
            ObserverP2pBootstrap::new(above_capacity),
            Err(
                ObserverP2pBootstrapError::ObserverCountExceedsConnectionCapacity {
                    requested: above_capacity,
                    maximum: capacity,
                }
            )
        );
        let bootstrap = ObserverP2pBootstrap::new(1).expect("one observer is valid alone");
        assert_eq!(
            bootstrap.validate_for_validators(usize::MAX, capacity),
            Err(ObserverP2pBootstrapError::ParticipantCountOverflow {
                validators: usize::MAX,
                observers: 1,
            })
        );
        assert_eq!(
            bootstrap.validate_for_validators(above_capacity, capacity),
            Err(ObserverP2pBootstrapError::FanoutExceedsConnectionCapacity {
                validators: above_capacity,
                observers: 1,
                required: above_capacity,
                capacity,
            })
        );
        let exact_cap_observers = capacity
            .checked_sub(MAX_VALIDATORS_PER_HEIGHT - 1)
            .expect("connection cap accommodates the maximum revision-4 committee");
        let exact_cap_bootstrap =
            ObserverP2pBootstrap::new(exact_cap_observers).expect("exact-cap observer recipe");
        assert!(
            NetworkBuilder::new()
                .with_peers(MAX_VALIDATORS_PER_HEIGHT)
                .with_observer_p2p_bootstrap(exact_cap_bootstrap)
                .is_ok(),
            "maximum revision-4 committee plus exact-cap observers remains valid"
        );
        let over_cap_bootstrap = ObserverP2pBootstrap::new(exact_cap_observers + 1)
            .expect("one-over-fanout observer count remains below the raw observer cap");
        assert!(
            NetworkBuilder::new()
                .with_peers(MAX_VALIDATORS_PER_HEIGHT)
                .with_observer_p2p_bootstrap(over_cap_bootstrap)
                .is_err(),
            "one participant above the full-fanout cap must be rejected"
        );
    }
    #[test]
    fn observer_slow_reader_relay_rewrites_only_observer_addresses_without_leaking_targets() {
        let config = ObserverSlowReaderRelayConfig::new(1_024, Duration::from_millis(2))
            .expect("bounded relay config");
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_base_seed(stringify!(
                    observer_slow_reader_relay_rewrites_only_observer_addresses_without_leaking_targets
                ))
                .with_observer_p2p_bootstrap(
                    ObserverP2pBootstrap::new(5).expect("bounded observer recipe"),
                )
                .expect("bounded participant fanout")
                .with_observer_slow_reader_relays(config)
                .expect("observer bootstrap precedes relay config"),
        );
        let relays = network
            .observer_slow_reader_relays
            .as_ref()
            .expect("relay harness is present");
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("relay control runtime");
        let paused = runtime
            .block_on(network.pause_observer_slow_reader_relays())
            .expect("relay hook returns a pause owner");
        assert!(relays.forwarding.try_read().is_err());
        drop(paused);
        assert!(relays.forwarding.try_read().is_ok());
        assert_eq!(relays.routes.len(), network.observers().len());
        assert_eq!(
            network.observer_slow_reader_relay_stats(),
            Some(ObserverSlowReaderRelayStats::default())
        );
        for observer in network.observers() {
            assert_eq!(
                network.observer_slow_reader_relay_stats_for(&observer.id()),
                Some(ObserverSlowReaderRelayStats::default())
            );
        }
        assert_eq!(
            network.observer_slow_reader_relay_stats_for(&network.validators()[0].id()),
            None
        );
        let trusted_layer = network
            .config_layers()
            .next()
            .expect("trusted peer layer")
            .into_owned();
        let trusted = trusted_layer
            .get("trusted_peers")
            .and_then(Value::as_array)
            .expect("trusted peer array");
        assert_eq!(trusted.len(), network.all_peers().count());
        for (index, peer) in network.all_peers().enumerate() {
            let advertised = network.advertised_p2p_address(peer);
            let advertised_literal = advertised.to_literal();
            let expected = format!("{}@{}", peer.network_peer_id(), advertised_literal);
            assert_eq!(trusted[index].as_str(), Some(expected.as_str()));
            if network.observers().contains(peer) {
                assert_ne!(advertised, peer.p2p_address());
                let real = peer.p2p_address().to_literal();
                assert!(
                    trusted.iter().all(|entry| {
                        entry
                            .as_str()
                            .is_none_or(|literal| !literal.contains(&real))
                    }),
                    "real observer listener {real} leaked into trusted peers"
                );
                let observer_layer = network.observer_start_layer(peer);
                assert_eq!(
                    get_nested_value(&observer_layer, &["network", "public_address"])
                        .and_then(Value::as_str),
                    Some(advertised_literal.as_str())
                );
                assert_eq!(
                    get_nested_value(&observer_layer, &["network", "connect_startup_delay_ms"])
                        .and_then(Value::as_integer),
                    Some(
                        i64::try_from(OBSERVER_RELAY_OUTBOUND_DIAL_DELAY.as_millis())
                            .expect("test delay fits i64")
                    )
                );
            } else {
                assert_eq!(advertised, peer.p2p_address());
            }
        }
    }
    #[test]
    fn observer_slow_reader_relay_config_is_bounded_and_requires_observers() {
        assert_eq!(
            ObserverSlowReaderRelayConfig::new(0, Duration::from_millis(1)),
            Err(ObserverSlowReaderRelayError::ZeroReadChunkBytes)
        );
        let above_chunk = ObserverSlowReaderRelayConfig::maximum_read_chunk_bytes()
            .checked_add(1)
            .expect("chunk limit fits usize");
        assert_eq!(
            ObserverSlowReaderRelayConfig::new(above_chunk, Duration::from_millis(1)),
            Err(ObserverSlowReaderRelayError::ReadChunkBytesExceedsLimit {
                requested: above_chunk,
                maximum: ObserverSlowReaderRelayConfig::maximum_read_chunk_bytes(),
            })
        );
        assert_eq!(
            ObserverSlowReaderRelayConfig::new(1, Duration::ZERO),
            Err(ObserverSlowReaderRelayError::ZeroReadDelay)
        );
        let above_delay = ObserverSlowReaderRelayConfig::maximum_read_delay()
            .checked_add(Duration::from_nanos(1))
            .expect("delay limit can be incremented");
        assert_eq!(
            ObserverSlowReaderRelayConfig::new(1, above_delay),
            Err(ObserverSlowReaderRelayError::ReadDelayExceedsLimit {
                requested: above_delay,
                maximum: ObserverSlowReaderRelayConfig::maximum_read_delay(),
            })
        );
        let valid = ObserverSlowReaderRelayConfig::new(1, Duration::from_millis(1))
            .expect("minimum bounded config");
        assert!(matches!(
            NetworkBuilder::new().with_observer_slow_reader_relays(valid),
            Err(ObserverSlowReaderRelayError::MissingObserverBootstrap)
        ));
    }
    #[tokio::test]
    async fn observer_slow_reader_relay_is_byte_transparent_and_joins_active_connection() {
        if skip_network_tests(
            "observer_slow_reader_relay_is_byte_transparent_and_joins_active_connection",
        ) {
            return;
        }
        let upstream_listener = TokioTcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock observer listener");
        let upstream_address = SocketAddr::from(
            upstream_listener
                .local_addr()
                .expect("mock observer listener has an address"),
        );
        let published_port = AllocatedPort::new();
        let published_address = socket_addr!(127.0.0.1:*published_port);
        let config = ObserverSlowReaderRelayConfig::new(31, Duration::from_millis(1))
            .expect("bounded relay config");
        let counters = Arc::new(ObserverSlowReaderRelayCounters::default());
        let peer_id = PeerId::new(PEER_KEYPAIR.public_key().clone());
        let relays = ObserverSlowReaderRelays {
            config,
            routes: vec![ObserverSlowReaderRelayRoute {
                peer_id: peer_id.clone(),
                published_address: published_address.clone(),
                upstream_address,
                counters: Arc::clone(&counters),
                _published_port: published_port,
            }],
            published_addresses: HashMap::from([(peer_id.clone(), published_address.clone())]),
            running: AtomicBool::new(false),
            forwarding: Arc::new(RwLock::new(())),
            runtime: StdMutex::new(ObserverSlowReaderRelayRuntime::default()),
        };
        relays.start().await.expect("start transparent relay");
        relays.start().await.expect("repeated start is idempotent");
        let payload = (0_u32..4_096)
            .map(|index| index.wrapping_mul(73).wrapping_add(19).to_le_bytes()[0])
            .collect::<Vec<_>>();
        let reply = vec![0x00, 0xFF, 0xC3, 0x28, 0x80, 0x01, 0xFE, 0x7F];
        let expected_payload = payload.clone();
        let expected_reply = reply.clone();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = upstream_listener
                .accept()
                .await
                .expect("relay connects to mock observer");
            let mut received = vec![0_u8; expected_payload.len()];
            socket
                .read_exact(&mut received)
                .await
                .expect("mock observer receives complete opaque payload");
            assert_eq!(received, expected_payload);
            socket
                .write_all(&expected_reply)
                .await
                .expect("mock observer returns opaque response");
            let mut trailing = [0_u8; 1];
            assert_eq!(
                socket
                    .read(&mut trailing)
                    .await
                    .expect("observe relay connection shutdown"),
                0,
                "relay shutdown must close its active upstream connection",
            );
        });
        let mut client = TcpStream::connect(published_address.to_string())
            .await
            .expect("connect validator side to relay");
        let paused = relays.pause().await;
        client
            .write_all(&payload)
            .await
            .expect("send opaque validator payload");
        timeout(Duration::from_secs(2), async {
            loop {
                if counters.delayed_reads.load(Ordering::Relaxed) > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("relay reached its deterministic forwarding pause");
        assert_eq!(
            counters
                .forwarded_to_observers_bytes
                .load(Ordering::Relaxed),
            0,
            "paused relay must not forward a byte it has already read",
        );
        drop(paused);
        let mut received_reply = vec![0_u8; reply.len()];
        timeout(
            Duration::from_secs(5),
            client.read_exact(&mut received_reply),
        )
        .await
        .expect("relay response stayed within the test bound")
        .expect("receive complete opaque observer response");
        assert_eq!(received_reply, reply);
        timeout(Duration::from_secs(2), relays.shutdown())
            .await
            .expect("relay listener and active child joined within the shutdown bound");
        timeout(Duration::from_secs(2), upstream)
            .await
            .expect("mock observer saw connection closure within the shutdown bound")
            .expect("mock observer task did not panic");
        assert!(!relays.running.load(Ordering::Acquire));
        assert!(
            TcpStream::connect(published_address.to_string())
                .await
                .is_err(),
            "shutdown must release the published listener"
        );
        let stats = counters.snapshot();
        assert_eq!(stats.accepted_connections, 1);
        assert_eq!(stats.upstream_connections, 1);
        assert!(stats.delayed_reads > 1);
        assert_eq!(
            stats.forwarded_to_observers_bytes,
            u64::try_from(payload.len()).expect("test payload length fits u64")
        );
        assert_eq!(relays.stats_for(&peer_id), Some(stats));
    }
    #[tokio::test]
    async fn observer_relay_pause_acknowledges_only_after_inflight_write_and_counter_retire() {
        // A one-byte output buffer makes a real write_all remain partially
        // complete. No mock counter or sleep stands in for the write owner.
        let (mut validator, reader) = tokio::io::duplex(16);
        let (writer, mut observer) = tokio::io::duplex(1);
        let config = ObserverSlowReaderRelayConfig::new(8, Duration::from_millis(1))
            .expect("bounded relay config");
        let counters = Arc::new(ObserverSlowReaderRelayCounters::default());
        let relays = ObserverSlowReaderRelays {
            config,
            routes: Vec::new(),
            published_addresses: HashMap::new(),
            running: AtomicBool::new(false),
            forwarding: Arc::new(RwLock::new(())),
            runtime: StdMutex::new(ObserverSlowReaderRelayRuntime::default()),
        };
        let (shutdown, shutdown_rx) = watch::channel(false);
        let copy = tokio::spawn(slow_copy_observer_ciphertext(
            reader,
            writer,
            config,
            Arc::clone(&counters),
            shutdown_rx,
            Arc::clone(&relays.forwarding),
        ));
        validator
            .write_all(b"ABCD")
            .await
            .expect("first opaque read");
        let mut first = [0_u8; 1];
        timeout(Duration::from_secs(2), observer.read_exact(&mut first))
            .await
            .expect("first write began")
            .expect("first byte forwarded");
        assert_eq!(first, *b"A");
        assert_eq!(counters.snapshot().forwarded_to_observers_bytes, 0);
        let pause = relays.pause();
        tokio::pin!(pause);
        assert!(
            futures::poll!(&mut pause).is_pending(),
            "pause must not acknowledge a partially completed write_all"
        );
        let mut rest = [0_u8; 3];
        timeout(Duration::from_secs(2), observer.read_exact(&mut rest))
            .await
            .expect("old write finishes")
            .expect("remaining opaque bytes");
        assert_eq!(rest, *b"BCD");
        let paused = timeout(Duration::from_secs(2), &mut pause)
            .await
            .expect("pause follows old write retirement");
        assert_eq!(
            counters.snapshot().forwarded_to_observers_bytes,
            4,
            "the read owner must retain the completed-byte update until acknowledgement"
        );
        validator
            .write_all(b"EF")
            .await
            .expect("new opaque read during hold");
        timeout(Duration::from_secs(2), async {
            while counters.snapshot().delayed_reads != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("copy read the new ciphertext before blocking at the same gate");
        assert_eq!(counters.snapshot().forwarded_to_observers_bytes, 4);
        assert!(relays.forwarding.try_read().is_err());
        drop(paused);
        let mut fresh = [0_u8; 2];
        timeout(Duration::from_secs(2), observer.read_exact(&mut fresh))
            .await
            .expect("release forwards new read")
            .expect("new opaque bytes");
        assert_eq!(fresh, *b"EF");
        timeout(Duration::from_secs(2), async {
            while counters.snapshot().forwarded_to_observers_bytes != 6 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("released write and counter retire");
        shutdown
            .send(true)
            .expect("copy still owns shutdown receiver");
        timeout(Duration::from_secs(2), copy)
            .await
            .expect("copy joins")
            .expect("copy does not panic")
            .expect("copy shutdown succeeds");
    }

    #[tokio::test]
    async fn observer_relay_pause_covers_new_connections_and_shutdown_joins_while_held() {
        let upstream_listener = TokioTcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock observer listener");
        let upstream_address = SocketAddr::from(upstream_listener.local_addr().unwrap());
        let published_port = AllocatedPort::new();
        let published_address = socket_addr!(127.0.0.1:*published_port);
        let config = ObserverSlowReaderRelayConfig::new(8, Duration::from_millis(1))
            .expect("bounded relay config");
        let counters = Arc::new(ObserverSlowReaderRelayCounters::default());
        let peer_id = PeerId::new(PEER_KEYPAIR.public_key().clone());
        let relays = ObserverSlowReaderRelays {
            config,
            routes: vec![ObserverSlowReaderRelayRoute {
                peer_id: peer_id.clone(),
                published_address: published_address.clone(),
                upstream_address,
                counters: Arc::clone(&counters),
                _published_port: published_port,
            }],
            published_addresses: HashMap::from([(peer_id, published_address.clone())]),
            running: AtomicBool::new(false),
            forwarding: Arc::new(RwLock::new(())),
            runtime: StdMutex::new(ObserverSlowReaderRelayRuntime::default()),
        };
        relays.start().await.expect("start transparent relay");
        let mut first = TcpStream::connect(published_address.to_string())
            .await
            .unwrap();
        let (mut first_observer, _) = timeout(Duration::from_secs(2), upstream_listener.accept())
            .await
            .expect("first connection bounded")
            .unwrap();
        first.write_all(b"warm").await.unwrap();
        let mut warm = [0_u8; 4];
        timeout(Duration::from_secs(2), first_observer.read_exact(&mut warm))
            .await
            .expect("established forwarding bounded")
            .unwrap();
        assert_eq!(warm, *b"warm");
        let paused = timeout(Duration::from_secs(2), relays.pause())
            .await
            .expect("pause established connection");
        let before = counters.snapshot();
        assert_eq!(before.forwarded_to_observers_bytes, 4);
        assert_eq!(before.upstream_connections, 1);
        // The connection did not exist at acknowledgement; it must share the
        // same exclusive gate rather than obtain a new unpaused authority.
        let mut late = TcpStream::connect(published_address.to_string())
            .await
            .unwrap();
        let (mut late_observer, _) = timeout(Duration::from_secs(2), upstream_listener.accept())
            .await
            .expect("late connection bounded")
            .unwrap();
        late.write_all(b"new").await.unwrap();
        timeout(Duration::from_secs(2), async {
            loop {
                let stats = counters.snapshot();
                if stats.upstream_connections == 2 && stats.delayed_reads > before.delayed_reads {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late connection reader reached held forwarding gate");
        assert_eq!(counters.snapshot().forwarded_to_observers_bytes, 4);
        timeout(Duration::from_secs(2), relays.shutdown())
            .await
            .expect("shutdown cancels gate waiters and joins every connection while held");
        let mut trailing = [0_u8; 1];
        assert_eq!(
            timeout(Duration::from_secs(2), first_observer.read(&mut trailing))
                .await
                .expect("old upstream closes")
                .unwrap(),
            0
        );
        assert_eq!(
            timeout(Duration::from_secs(2), late_observer.read(&mut trailing))
                .await
                .expect("new upstream closes")
                .unwrap(),
            0
        );
        let stats = counters.snapshot();
        assert_eq!(stats.accepted_connections, 2);
        assert_eq!(stats.upstream_connections, 2);
        assert_eq!(stats.forwarded_to_observers_bytes, 4);
        assert!(!relays.running.load(Ordering::Acquire));
        assert!(
            TcpStream::connect(published_address.to_string())
                .await
                .is_err()
        );
        drop(paused);
        assert!(relays.forwarding.try_read().is_ok());
    }

    #[test]
    fn default_builder_has_no_observers_and_preserves_validator_peer_semantics() {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        assert_eq!(network.peers().as_slice(), network.validators());
        assert!(network.observers().is_empty());
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("relay control runtime");
        assert!(
            runtime
                .block_on(network.pause_observer_slow_reader_relays())
                .is_none()
        );
        assert_eq!(network.all_peers().count(), network.peers().len());
        assert_eq!(network.torii_urls().len(), network.peers().len());
        assert_eq!(network.topology_entries().len(), network.peers().len());
        assert!(network.observer_advertised_p2p_addresses.is_empty());
        assert_eq!(network.observer_slow_reader_relay_stats(), None);
        let trusted = network
            .config_layers()
            .next()
            .expect("trusted layer")
            .into_owned();
        let entries = trusted
            .get("trusted_peers")
            .and_then(Value::as_array)
            .expect("trusted peers");
        for peer in network.peers() {
            let expected = format!(
                "{}@{}",
                peer.network_peer_id(),
                peer.p2p_address().to_literal()
            );
            assert!(
                entries
                    .iter()
                    .any(|entry| entry.as_str() == Some(&expected))
            );
        }
    }
    #[test]
    fn config_layers_allow_local_preauth_bypass() {
        let network = NetworkBuilder::new().build();
        let layers: Vec<_> = network.config_layers().collect();
        let allowlist = layers
            .iter()
            .find_map(|layer| {
                layer
                    .as_ref()
                    .get("torii")
                    .and_then(toml::Value::as_table)
                    .and_then(|torii| torii.get("preauth_allow_cidrs"))
                    .and_then(toml::Value::as_array)
            })
            .expect("preauth_allow_cidrs array");
        let entries: Vec<&str> = allowlist.iter().filter_map(toml::Value::as_str).collect();
        assert!(
            entries.contains(&"127.0.0.1/32"),
            "IPv4 loopback should bypass pre-auth gating"
        );
        assert!(
            entries.contains(&"::1/128"),
            "IPv6 loopback should bypass pre-auth gating"
        );
    }
    #[test]
    fn default_builder_omits_retired_nexus_switch() {
        let NetworkBuilder { config_layers, .. } = NetworkBuilder::new();
        let omits_retired_switch = config_layers
            .iter()
            .all(|layer| read_bool(layer, &["nexus", "enabled"]).is_none());
        assert!(
            omits_retired_switch,
            "default NetworkBuilder must not write the retired Nexus switch"
        );
    }
    #[test]
    fn default_builder_scales_concurrency_defaults() {
        let NetworkBuilder { config_layers, .. } = NetworkBuilder::new();
        let base = config_layers
            .iter()
            .find(|layer| layer.get("concurrency").is_some())
            .expect("base config layer should include concurrency defaults");
        let concurrency = base
            .get("concurrency")
            .and_then(toml::Value::as_table)
            .expect("concurrency table");
        let expected =
            i64::try_from(test_concurrency_threads()).expect("test concurrency threads fit in i64");
        assert_eq!(
            concurrency
                .get("scheduler_min_threads")
                .and_then(toml::Value::as_integer),
            Some(expected)
        );
        assert_eq!(
            concurrency
                .get("scheduler_max_threads")
                .and_then(toml::Value::as_integer),
            Some(expected)
        );
        assert_eq!(
            concurrency
                .get("rayon_global_threads")
                .and_then(toml::Value::as_integer),
            Some(expected)
        );
        let pipeline = base
            .get("pipeline")
            .and_then(toml::Value::as_table)
            .expect("pipeline table");
        assert_eq!(
            pipeline.get("workers").and_then(toml::Value::as_integer),
            Some(expected)
        );
    }
    #[test]
    fn builder_config_layers_parse_with_required_genesis_fields() {
        let env = Environment::new();
        let peer = NetworkPeerBuilder::new().build(&env);
        let NetworkBuilder {
            config_layers,
            genesis_key_pair,
            ..
        } = NetworkBuilder::new();
        let bls_public_key = peer
            .bls_public_key()
            .expect("test peer should have BLS key");
        let bls_pop = peer.bls_pop().expect("test peer should have BLS PoP");
        let mut pop_entry = Table::new();
        pop_entry.insert(
            "public_key".into(),
            Value::String(bls_public_key.to_string()),
        );
        pop_entry.insert(
            "pop_hex".into(),
            Value::String(format!("0x{}", hex_lower(bls_pop))),
        );
        let trusted_peers_pop = Value::Array(vec![Value::Table(pop_entry)]);
        let mut layers = Vec::with_capacity(config_layers.len() + 1);
        layers.push(
            Table::new()
                .write("chain", config::chain_id().to_string())
                .write(
                    ["genesis", "public_key"],
                    genesis_key_pair.public_key().to_string(),
                )
                .write(["trusted_peers_pop"], trusted_peers_pop),
        );
        layers.extend(config_layers);
        let actual = resolve_actual_config(&peer, &layers)
            .expect("builder config layers should parse once chain/genesis are provided");
        assert_eq!(
            actual.genesis.expected_hash.to_string(),
            NON_RUNTIME_GENESIS_EXPECTED_HASH_BODY_FOR_CONFIG_PROJECTION,
            "pre-genesis projection must receive only the non-runtime schema sentinel"
        );
    }
    #[test]
    fn generated_network_configs_parse_for_legal_roster_scales() {
        init_instruction_registry();
        for validator_count in [4, 7, MAX_VALIDATORS_PER_HEIGHT] {
            let expected_chain = format!("scaled-npos-roster-{validator_count}");
            let caller_chain = expected_chain.clone();
            let network = build_with_isolated_permit(
                NetworkBuilder::new()
                    .with_peers(validator_count)
                    .with_npos_consensus()
                    .with_base_seed(format!(
                        "generated_network_configs_parse_for_legal_roster_scales_{validator_count}"
                    ))
                    .with_config_layer(move |layer| {
                        layer.write("chain", caller_chain);
                    }),
            );
            assert_eq!(
                network.chain_id().to_string(),
                expected_chain,
                "the roster-scaled pre-genesis projection must retain the caller chain"
            );
            let layers = network
                .config_layers()
                .map(Cow::into_owned)
                .collect::<Vec<_>>();
            let actual = resolve_final_actual_config(&network.peers()[0], &layers);
            assert_eq!(
                actual.common.trusted_peers.value().validator_roster_len(),
                validator_count
            );
            assert_eq!(actual.common.chain, network.chain_id());
            assert_eq!(network.max_validator_capacity, validator_count);
            validate_planned_validator_capacity(&actual, validator_count)
                .expect("native participant connection capacity");
            let genesis = network.genesis();
            let source_limit =
                iroha_data_model::parameter::FastpqSourcePolicyV1::bootstrap().intrinsic;
            let registration_counts = genesis
                .0
                .external_transactions()
                .map(|transaction| match transaction.instructions() {
                    Executable::Instructions(instructions) => instructions
                        .iter()
                        .filter(|instruction| {
                            instruction.as_any().is::<RegisterPublicLaneValidator>()
                        })
                        .count(),
                    _ => panic!("genesis must contain instruction batches"),
                })
                .collect::<Vec<_>>();
            assert_eq!(registration_counts.iter().sum::<usize>(), validator_count);
            assert!(
                registration_counts.iter().all(|count| {
                    *count <= usize::try_from(source_limit.max_transcripts).unwrap()
                        && *count <= usize::try_from(source_limit.max_deltas).unwrap()
                }),
                "signed batch packing must preserve the per-entry stake transfer bound"
            );
        }
    }
    #[test]
    fn generated_capacity_layer_preserves_caller_lane_profile_limits() {
        init_instruction_registry();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_base_seed(stringify!(
                    generated_capacity_layer_preserves_caller_lane_profile_limits
                ))
                .with_config_layer(|layer| {
                    layer.write(["network", "lane_profile"], "home");
                }),
        );
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let actual = resolve_final_actual_config(&network.peers()[0], &layers);
        let home_capacity =
            iroha_config::parameters::defaults::network::lane_profile::HOME_MAX_TOTAL_CONNECTIONS;
        assert_eq!(
            effective_network_reply_source_capacity(&actual.network),
            home_capacity,
            "the generated Sumeragi layer must preserve the effective home-profile connection limit"
        );
        let observer_bootstrap =
            ObserverP2pBootstrap::new(home_capacity - 2).expect("observer count fits core bounds");
        assert_eq!(
            observer_bootstrap.validate_for_validators(
                network.validators().len(),
                effective_network_reply_source_capacity(&actual.network),
            ),
            Err(ObserverP2pBootstrapError::FanoutExceedsConnectionCapacity {
                validators: 4,
                observers: home_capacity - 2,
                required: home_capacity + 1,
                capacity: home_capacity,
            }),
            "observer fanout validation must use the lane-profile-derived capacity"
        );
    }
    #[test]
    fn final_generated_network_config_rejects_retired_queue_settings() {
        let panic = std::panic::catch_unwind(|| {
            build_with_isolated_permit(
                NetworkBuilder::new()
                    .with_peers(4)
                    .with_base_seed(stringify!(
                        final_generated_network_config_rejects_retired_queue_settings
                    ))
                    .with_config_layer(|layer| {
                        layer.write(["sumeragi", "queues", "bodies"], 8_192i64);
                    }),
            );
        })
        .expect_err("invalid final Sumeragi geometry must panic during network generation");
        let panic_message = panic
            .downcast_ref::<&str>()
            .map(std::string::ToString::to_string)
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<missing panic message>".to_owned());
        assert!(
            panic_message.contains("fully merged test-network config"),
            "final config failure should be localized, got: {panic_message}"
        );
    }
    fn assert_network_config_binds_exact_signed_genesis_hash(network: &Network) {
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let actual = resolve_actual_config(&network.peers()[0], &layers)
            .expect("generated network configuration must parse");
        let exact_hash = network.genesis().0.hash();
        assert_eq!(
            actual.genesis.expected_hash, exact_hash,
            "runtime config must bind the exact signed in-memory genesis header"
        );
        assert_ne!(
            actual.genesis.expected_hash.to_string(),
            NON_RUNTIME_GENESIS_EXPECTED_HASH_BODY_FOR_CONFIG_PROJECTION,
            "the projection sentinel must never escape into runtime network layers"
        );
        let projection_sentinel_literal = genesis_expected_hash_config_literal(
            NON_RUNTIME_GENESIS_EXPECTED_HASH_BODY_FOR_CONFIG_PROJECTION,
        );
        assert!(
            layers.iter().all(|layer| {
                get_nested_value(layer, &["genesis", "expected_hash"]).and_then(Value::as_str)
                    != Some(projection_sentinel_literal.as_str())
            }),
            "no emitted network config layer may contain the projection sentinel"
        );
    }
    #[test]
    fn network_config_layers_bind_default_and_custom_signed_genesis_expected_hashes() {
        init_instruction_registry();
        {
            let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
            assert_network_config_binds_exact_signed_genesis_hash(&network);
        }
        let custom =
            build_with_isolated_permit(NetworkBuilder::new().with_peers(4).with_genesis_block(
                |topology, topology_entries| {
                    genesis_factory(Vec::new(), topology, topology_entries)
                },
            ));
        assert_network_config_binds_exact_signed_genesis_hash(&custom);
    }
    #[test]
    fn caller_wrong_genesis_expected_hash_remains_effective_for_adversarial_startup() {
        // Iroha hashes carry an odd final-byte marker; keep this wrong anchor
        // canonical so the daemon reaches the hash-agreement check.
        const WRONG_HASH_BODY: &str =
            "0000000000000000000000000000000000000000000000000000000000000003";
        let wrong_hash_literal = genesis_expected_hash_config_literal(WRONG_HASH_BODY);
        let caller_wrong_hash_literal = wrong_hash_literal.clone();
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_peers(4).with_config_layer(
                move |layer| {
                    layer.write(["genesis", "expected_hash"], caller_wrong_hash_literal);
                },
            ));
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let anchors = layers
            .iter()
            .filter_map(|layer| {
                get_nested_value(layer, &["genesis", "expected_hash"]).and_then(Value::as_str)
            })
            .collect::<Vec<_>>();
        let exact_hash_literal =
            genesis_expected_hash_config_literal(&network.genesis().0.hash().to_string());
        assert_eq!(
            anchors,
            [exact_hash_literal.as_str(), wrong_hash_literal.as_str()],
            "the generated anchor must precede a caller override"
        );
        let actual = resolve_actual_config(&network.peers()[0], &layers)
            .expect("a canonical wrong hash must remain syntactically valid");
        assert_eq!(actual.genesis.expected_hash.to_string(), WRONG_HASH_BODY);
        assert_ne!(
            actual.genesis.expected_hash,
            network.genesis().0.hash(),
            "the harness must not repair an adversarial caller override"
        );
    }
    #[test]
    fn config_layers_without_pop_excludes_bls_entries() {
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .without_auto_populated_trusted_peers()
                .with_peers(4),
        );
        let mut layers = network.config_layers();
        let _trusted = layers.next().expect("trusted peers layer");
        let base = layers.next().expect("base config layer").into_owned();
        assert!(base.get("trusted_peers_bls").is_none());
        assert!(base.get("trusted_peers_pop").is_none());
    }
    #[test]
    fn default_network_has_no_da_toggle() {
        let network = NetworkBuilder::new().build();
        let mut layers = network.config_layers();
        let _trusted = layers.next().expect("trusted peers layer");
        let base = layers.next().expect("base config layer").into_owned();
        let sumeragi = base
            .get("sumeragi")
            .unwrap_or_else(|| {
                let keys = base.keys().cloned().collect::<Vec<_>>();
                panic!("missing sumeragi table; keys={keys:?}")
            })
            .as_table()
            .expect("sumeragi entry must be a table");
        assert!(
            get_nested_value(sumeragi, &["da", "enabled"]).is_none(),
            "mandatory DA must not be represented by a local boolean toggle"
        );
    }
    #[test]
    fn base_config_contains_only_native_consensus_settings() {
        let network = build_with_isolated_permit(NetworkBuilder::new());
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        assert!(
            layers
                .iter()
                .all(|layer| get_nested_value(layer, &["sumeragi", "queues"]).is_none())
        );
        let actual = resolve_final_actual_config(&network.peers()[0], &layers);
        validate_planned_validator_capacity(&actual, DEFAULT_NETWORK_PEERS)
            .expect("native defaults cover the committee");
    }
    #[tokio::test]
    async fn peer_bootstrap_stages_start_global_and_committee_before_observers() {
        let (global_started_tx, global_started_rx) = tokio::sync::oneshot::channel();
        let (global_release_tx, global_release_rx) = tokio::sync::oneshot::channel();
        let (committee_started_tx, committee_started_rx) = tokio::sync::oneshot::channel();
        let (committee_release_tx, committee_release_rx) = tokio::sync::oneshot::channel();
        let observer_started = Arc::new(AtomicBool::new(false));
        let observer_started_for_task = Arc::clone(&observer_started);

        let global_validators = async move {
            global_started_tx
                .send(())
                .map_err(|()| "global start receiver dropped")?;
            global_release_rx
                .await
                .map_err(|_| "global release sender dropped")?;
            Ok::<(), &'static str>(())
        };
        let committee_validators = async move {
            committee_started_tx
                .send(())
                .map_err(|()| "committee start receiver dropped")?;
            committee_release_rx
                .await
                .map_err(|_| "committee release sender dropped")?;
            Ok::<(), &'static str>(())
        };
        let observers = async move {
            observer_started_for_task.store(true, Ordering::Release);
            Ok::<(), &'static str>(())
        };
        let bootstrap = tokio::spawn(run_peer_bootstrap_stages(
            global_validators,
            committee_validators,
            observers,
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            global_started_rx
                .await
                .expect("global validator cohort should start");
            committee_started_rx
                .await
                .expect("committee validator cohort should start concurrently");
        })
        .await
        .expect("both validator cohorts should start without either completing");
        assert!(
            !observer_started.load(Ordering::Acquire),
            "observers must remain gated while validator cohorts are starting"
        );

        global_release_tx
            .send(())
            .expect("global validator cohort should still be waiting");
        tokio::task::yield_now().await;
        assert!(
            !observer_started.load(Ordering::Acquire),
            "observers must remain gated until the committee cohort also completes"
        );

        committee_release_tx
            .send(())
            .expect("committee validator cohort should still be waiting");
        tokio::time::timeout(Duration::from_secs(1), bootstrap)
            .await
            .expect("bootstrap stages should complete after both cohorts are released")
            .expect("bootstrap task should not panic")
            .expect("bootstrap stages should succeed");
        assert!(
            observer_started.load(Ordering::Acquire),
            "observers should start after both validator cohorts complete"
        );
    }
    #[tokio::test]
    async fn can_start_networks() {
        if skip_network_tests("can_start_networks") {
            return;
        }
        let (first_builder, second_builder) = (
            NetworkBuilder::new().with_peers(4),
            NetworkBuilder::new().with_peers(4),
        );
        {
            let _program_guard = lock_env_guard_async(&PROGRAM_BIN_ENV_GUARD).await;
            tokio::time::timeout(
                Duration::from_secs(20 * 60),
                Program::Irohad.resolve_async(),
            )
            .await
            .expect("iroha3d binary resolution should not hang")
            .expect("iroha3d binary should resolve for network startup tests");
        }
        let first = build_with_isolated_permit_async(first_builder).await;
        let first_timeout = first
            .peer_startup_timeout()
            .saturating_add(Duration::from_secs(30));
        tokio::time::timeout(first_timeout, first.start_all())
            .await
            .expect("first network startup should complete within timeout")
            .unwrap();
        tokio::time::timeout(first_timeout, async {
            first.shutdown().await;
        })
        .await
        .expect("first network shutdown should complete within timeout");
        drop(first);
        // Single-peer DA startup is still stall-prone in integration paths; keep this
        // smoke test on quorum-representative topologies to avoid lock convoy hangs.
        let second = build_with_isolated_permit_async(second_builder).await;
        let second_timeout = second
            .peer_startup_timeout()
            .saturating_add(Duration::from_secs(30));
        tokio::time::timeout(second_timeout, second.start_all())
            .await
            .expect("second network startup should complete within timeout")
            .unwrap();
        tokio::time::timeout(second_timeout, async {
            second.shutdown().await;
        })
        .await
        .expect("second network shutdown should complete within timeout");
    }
    #[tokio::test]
    async fn start_fails_with_missing_binary() {
        if skip_network_tests("start_fails_with_missing_binary") {
            return;
        }
        let network = build_with_isolated_permit_async(NetworkBuilder::new()).await;
        let _program_guard = lock_env_guard_async(&PROGRAM_BIN_ENV_GUARD).await;
        const ENV: &str = PROGRAM_IROHAD_ENV;
        let old = std::env::var(ENV).ok();
        set_env_var(ENV, "non-existent-path");
        let res = tokio::time::timeout(Duration::from_secs(10), network.start_all())
            .await
            .expect("missing binary should fail startup quickly");
        assert!(res.is_err());
        if let Some(val) = old {
            set_env_var(ENV, val);
        } else {
            remove_env_var(ENV);
        }
    }
    #[tokio::test]
    async fn starts_single_peer_with_minimal_genesis_fallback() {
        if skip_network_tests("starts_single_peer_with_minimal_genesis_fallback") {
            return;
        }
        // Single-peer DA startup is still stall-prone in test environments.
        // Use a quorum-representative topology while preserving fallback-genesis coverage.
        let builder = NetworkBuilder::new()
            .with_peers(4)
            // Fallback-genesis coverage is not a low-latency consensus gate.
            // Give follower body validation a contention-tolerant signed
            // round budget, matching the focused four-peer query surface.
            .with_block_cadence(Duration::from_secs(4));
        {
            let _program_guard = lock_env_guard_async(&PROGRAM_BIN_ENV_GUARD).await;
            tokio::time::timeout(
                Duration::from_secs(20 * 60),
                Program::Irohad.resolve_async(),
            )
            .await
            .expect("iroha3d binary resolution should not hang")
            .expect("iroha3d binary should resolve for fallback startup test");
        }
        // Intentionally avoid providing a default executor sample; in CI the
        // prebuilt samples are usually absent so JSON genesis will fail to
        // locate `defaults/executor.to` and the harness will fall back to a
        // minimal in-memory genesis. This test ensures that even with fallback
        // the peer starts and commits the genesis block.
        // The binary was resolved above. Keep a release runner's lookup-only,
        // source-manifest-bound program contract intact for the actual startup.
        let network = build_with_isolated_permit_async(builder).await;
        let startup_timeout = network
            .peer_startup_timeout()
            .saturating_add(Duration::from_secs(30));
        let net = tokio::time::timeout(startup_timeout, network.start_all())
            .await
            .expect("fallback startup should complete within timeout");
        assert!(net.is_ok(), "network should start with fallback genesis");
    }
    #[test]
    fn ivm_fuel_config_defaults_to_unset() {
        assert!(matches!(IvmFuelConfig::default(), IvmFuelConfig::Unset));
    }
    #[test]
    fn default_builder_omits_retired_da_parameter() {
        let network = NetworkBuilder::new().build();
        let has_sumeragi_parameter = network.genesis_isi().iter().flatten().any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<SetParameter>()
                .is_some_and(|set_param| matches!(set_param.inner(), Parameter::Sumeragi(_)))
        });
        assert!(
            !has_sumeragi_parameter,
            "mandatory DA must not be encoded as a mutable Sumeragi parameter"
        );
    }
    #[test]
    fn original_npos_genesis_capacity_reader_preserves_refusal_and_same_input_retry() {
        let expected = SumeragiNposParameters::default();
        let parameter = expected.clone().into_custom_parameter();
        let original = parameter.payload().get().to_owned();
        let genesis = vec![vec![InstructionBox::from(SetParameter::new(
            Parameter::Custom(parameter.clone()),
        ))]];
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let producer = norito::with_decode_limits_scope(limits, || {
            SumeragiNposParameters::from_custom_parameter(&parameter)
        })
        .unwrap_err();
        assert!(
            matches!(
                producer,
                norito::json::Error::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                )
            ),
            "{producer:?}"
        );
        let parser =
            norito::with_decode_limits_scope(limits, || npos_params_from_genesis(&genesis, &[]))
                .unwrap_err();
        assert!(
            matches!(
                parser.downcast_ref::<norito::json::Error>(),
                Some(norito::json::Error::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                ))
            ),
            "{parser:?}"
        );
        let capacity = norito::with_decode_limits_scope(limits, || {
            authenticated_validator_capacity(4, ConsensusMode::Npos, &genesis, &[])
        })
        .unwrap_err();
        assert!(
            matches!(
                capacity.downcast_ref::<norito::json::Error>(),
                Some(norito::json::Error::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                ))
            ),
            "{capacity:?}"
        );
        assert_eq!(parameter.payload().get(), &original);
        assert_eq!(
            npos_params_from_genesis(&genesis, &[]).unwrap(),
            Some(expected.clone())
        );
        assert_eq!(
            authenticated_validator_capacity(4, ConsensusMode::Npos, &genesis, &[]).unwrap(),
            usize::try_from(expected.max_validators()).unwrap().max(4)
        );
    }
    #[test]
    fn npos_genesis_snapshot_parser_rejects_invalid_payload() {
        let mut invalid = SumeragiNposParameters::default();
        invalid.epoch_seed = [0; 32];
        let genesis = vec![vec![InstructionBox::from(SetParameter::new(
            Parameter::Custom(invalid.into_custom_parameter()),
        ))]];
        let error = npos_params_from_genesis(&genesis, &[])
            .expect_err("an all-zero NPoS seed must be rejected");
        assert!(
            matches!(error.downcast_ref::<norito::json::Error>(),
                Some(norito::json::Error::InvalidField { field, message })
                    if field == "SumeragiNposParameters" && message == "epoch_seed must not be all zero"
            ),
            "{error:?}"
        );
    }
    #[test]
    fn npos_genesis_snapshot_parser_rejects_duplicates_across_sections() {
        let instruction = InstructionBox::from(SetParameter::new(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        )));
        let genesis = vec![vec![instruction.clone()]];
        let post_topology = vec![vec![instruction]];
        let error = npos_params_from_genesis(&genesis, &post_topology)
            .expect_err("multiple NPoS snapshots must be rejected");
        assert_eq!(
            error.to_string(),
            "genesis must contain exactly one `sumeragi_npos_parameters` snapshot"
        );
    }
    #[test]
    #[should_panic(expected = "permissioned genesis must omit `sumeragi_npos_parameters`")]
    fn permissioned_builder_rejects_npos_snapshot() {
        let parameter =
            Parameter::Custom(SumeragiNposParameters::default().into_custom_parameter());
        let _ = NetworkBuilder::new()
            .with_permissioned_consensus()
            .with_genesis_instruction(SetParameter::new(parameter))
            .build();
    }
    fn genesis_account_registration_count(network: &Network, account_id: &AccountId) -> usize {
        network
            .genesis()
            .0
            .external_transactions()
            .filter_map(|transaction| match transaction.instructions() {
                Executable::Instructions(instructions) => Some(instructions),
                _ => None,
            })
            .flatten()
            .filter(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterBox>()
                    .is_some_and(|register| {
                        matches!(
                            register,
                            RegisterBox::Account(register) if &register.object.id == account_id
                        )
                    })
            })
            .count()
    }
    fn genesis_instructions(network: &Network) -> Vec<InstructionBox> {
        network
            .genesis()
            .0
            .external_transactions()
            .filter_map(|transaction| match transaction.instructions() {
                Executable::Instructions(instructions) => Some(instructions.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }
    fn default_fee_asset_definition() -> AssetDefinitionId {
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("canonical fixture XOR asset")
    }
    fn registers_asset_definition(
        instructions: &[InstructionBox],
        definition: &AssetDefinitionId,
    ) -> bool {
        instructions.iter().any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterBox>()
                .is_some_and(|register| {
                    matches!(
                        register,
                        RegisterBox::AssetDefinition(register) if &register.object.id == definition
                    )
                })
        })
    }
    fn mints_to(
        instructions: &[InstructionBox],
        definition: &AssetDefinitionId,
        account: &AccountId,
    ) -> usize {
        let asset = AssetId::new(definition.clone(), account.clone());
        instructions
            .iter()
            .filter(|instruction| {
                instruction.as_any().downcast_ref::<MintBox>().is_some_and(
                    |mint| matches!(mint, MintBox::Asset(mint) if mint.destination == asset),
                )
            })
            .count()
    }
    /// Staking is NPoS-only (the network XOR identity lives in the NPoS parameters), so a
    /// permissioned genesis provisions the XOR fee resources and registers no public-lane
    /// validator; building the network pre-executes the genesis, so it also must execute.
    #[test]
    fn permissioned_builder_provisions_fees_without_staking() {
        init_instruction_registry();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_auto_populated_trusted_peers()
                .with_permissioned_consensus(),
        );
        assert_eq!(
            network.consensus_bootstrap_profile().mode_tag,
            PERMISSIONED_TAG,
        );
        let instructions = genesis_instructions(&network);
        assert!(
            !instructions.iter().any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterPublicLaneValidator>()
                    .is_some()
                    || instruction
                        .as_any()
                        .downcast_ref::<ActivatePublicLaneValidator>()
                        .is_some()
            }),
            "permissioned genesis must not stake public-lane validators",
        );
        let xor = default_fee_asset_definition();
        assert!(registers_asset_definition(&instructions, &xor));
        assert_eq!(mints_to(&instructions, &xor, &ALICE_ID), 1);
        for peer in network.peers() {
            assert_eq!(
                mints_to(&instructions, &xor, &peer.account_id()),
                1,
                "a permissioned validator receives fee funding and no stake",
            );
        }
    }
    #[test]
    fn permissioned_fee_bootstrap_skips_caller_owned_support_state() {
        init_instruction_registry();
        let nexus_domain = DomainId::try_new("nexus", "universal").expect("nexus domain");
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_permissioned_consensus()
                .with_genesis_instruction(Register::domain(Domain::new(nexus_domain))),
        );
        assert!(
            !registers_asset_definition(
                &genesis_instructions(&network),
                &default_fee_asset_definition()
            ),
            "the fee bootstrap must not merge into caller-owned reserved support state",
        );
    }
    #[test]
    fn permissioned_fee_bootstrap_skips_caller_owned_validator_account() {
        init_instruction_registry();
        let base_seed = stringify!(permissioned_fee_bootstrap_skips_caller_owned_validator_account);
        let peer_zero_seed = format!("{base_seed}-peer-0").into_bytes();
        let peer_zero_account = AccountId::new(
            checked_key_pair_from_seed(peer_zero_seed, Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_base_seed(base_seed)
                .with_permissioned_consensus()
                .with_genesis_instruction(Register::account(Account::new(
                    peer_zero_account.clone(),
                ))),
        );
        assert!(!registers_asset_definition(
            &genesis_instructions(&network),
            &default_fee_asset_definition()
        ));
        assert_eq!(
            genesis_account_registration_count(&network, &peer_zero_account),
            1,
            "the SoraCloud fallback must not register the caller-owned validator account again",
        );
    }
    #[test]
    fn npos_bootstrap_adds_validator_instructions() {
        init_instruction_registry();
        let stake_amount = SumeragiNposParameters::default().min_self_bond().clone();
        let network = NetworkBuilder::new()
            .with_peers(4)
            .with_auto_populated_trusted_peers()
            .with_npos_genesis_bootstrap(stake_amount)
            .build();
        assert_eq!(
            network.consensus_bootstrap_profile().mode_tag,
            NPOS_TAG,
            "NPoS bootstrap must select NPoS in signed genesis",
        );
        let genesis = network.genesis();
        let mut has_register = false;
        let mut has_activate = false;
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    if instruction
                        .as_any()
                        .downcast_ref::<RegisterPublicLaneValidator>()
                        .is_some()
                    {
                        has_register = true;
                    }
                    if instruction
                        .as_any()
                        .downcast_ref::<ActivatePublicLaneValidator>()
                        .is_some()
                    {
                        has_activate = true;
                    }
                }
            }
        }
        assert!(
            has_register && has_activate,
            "npos bootstrap should register and activate validators in genesis"
        );
    }
    #[test]
    fn autoscale_genesis_bootstrap_registers_committee_keys_for_global_peers() {
        init_instruction_registry();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_npos_consensus()
                .with_genesis_committee_keys_for_global_peers(),
        );
        let global_peers: HashSet<_> = network
            .peers
            .iter()
            .map(|peer| peer.id().public_key().clone())
            .collect();
        let mut committee_keys = HashSet::new();
        for tx in network.genesis().0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    if let Some(key) = instruction
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::consensus_keys::RegisterConsensusKey>()
                    {
                        assert_eq!(
                            key.id().role,
                            iroha_data_model::consensus::ConsensusKeyRole::Committee
                        );
                        assert!(global_peers.contains(&key.record().public_key));
                        assert!(committee_keys.insert(key.record().public_key.clone()));
                    }
                }
            }
        }
        assert_eq!(committee_keys, global_peers);
    }
    #[test]
    fn default_npos_builder_bootstraps_validators() {
        init_instruction_registry();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_auto_populated_trusted_peers()
                .with_npos_consensus(),
        );
        let genesis = network.genesis();
        let mut has_register = false;
        let mut has_activate = false;
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    if instruction
                        .as_any()
                        .downcast_ref::<RegisterPublicLaneValidator>()
                        .is_some()
                    {
                        has_register = true;
                    }
                    if instruction
                        .as_any()
                        .downcast_ref::<ActivatePublicLaneValidator>()
                        .is_some()
                    {
                        has_activate = true;
                    }
                }
            }
        }
        assert!(
            has_register && has_activate,
            "default NPoS builder should bootstrap validators in genesis"
        );
    }
    #[test]
    fn without_npos_genesis_bootstrap_skips_validator_instructions() {
        init_instruction_registry();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_auto_populated_trusted_peers()
                .with_npos_consensus()
                .without_npos_genesis_bootstrap(),
        );
        let genesis = network.genesis();
        let mut has_register = false;
        let mut has_activate = false;
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    if instruction
                        .as_any()
                        .downcast_ref::<RegisterPublicLaneValidator>()
                        .is_some()
                    {
                        has_register = true;
                    }
                    if instruction
                        .as_any()
                        .downcast_ref::<ActivatePublicLaneValidator>()
                        .is_some()
                    {
                        has_activate = true;
                    }
                }
            }
        }
        assert!(
            !has_register && !has_activate,
            "disabling NPoS bootstrap should not inject validator registration"
        );
    }
    #[test]
    fn post_topology_instructions_are_included_in_genesis() {
        init_instruction_registry();
        let domain_id: DomainId =
            DomainId::try_new("post_topology_test", "universal").expect("domain");
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_genesis_post_topology_isi(vec![
                    Register::domain(Domain::new(domain_id.clone())).into(),
                ]),
        );
        let genesis = network.genesis();
        let mut has_domain = false;
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    if instruction
                        .as_any()
                        .downcast_ref::<RegisterBox>()
                        .is_some_and(|register| match register {
                            RegisterBox::Domain(domain) => domain.object.id == domain_id,
                            _ => false,
                        })
                    {
                        has_domain = true;
                    }
                }
            }
        }
        assert!(
            has_domain,
            "post-topology instructions should be present in genesis"
        );
    }
    #[test]
    fn npos_bootstrap_clamps_to_min_self_bond() {
        init_instruction_registry();
        let mut npos_params = SumeragiNposParameters::default();
        npos_params.min_self_bond = npos_params
            .min_self_bond()
            .try_add(&Quantity::from(5_000_u64))
            .expect("test self-bond increment must remain representable");
        let expected = npos_params.min_self_bond.clone();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_auto_populated_trusted_peers()
                .with_genesis_instruction(SetParameter::new(Parameter::Custom(
                    npos_params.into_custom_parameter(),
                )))
                .with_npos_consensus(),
        );
        let genesis = network.genesis();
        let mut seen = false;
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    if let Some(register) = instruction
                        .as_any()
                        .downcast_ref::<RegisterPublicLaneValidator>()
                    {
                        seen = true;
                        assert_eq!(
                            register.initial_stake, expected,
                            "bootstrap stake must honor min_self_bond"
                        );
                    }
                }
            }
        }
        assert!(seen, "expected bootstrap validator registration in genesis");
    }
    #[test]
    fn npos_bootstrap_uses_post_topology_snapshot_min_self_bond() {
        init_instruction_registry();
        let mut npos_params = SumeragiNposParameters::default();
        npos_params.min_self_bond = npos_params
            .min_self_bond()
            .try_add(&Quantity::from(5_000_u64))
            .expect("test self-bond increment must remain representable");
        let expected = npos_params.min_self_bond.clone();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_auto_populated_trusted_peers()
                .with_genesis_post_topology_isi(vec![
                    SetParameter::new(Parameter::Custom(npos_params.into_custom_parameter()))
                        .into(),
                ])
                .with_npos_consensus(),
        );
        let profile = network.consensus_bootstrap_profile();
        assert_eq!(
            profile.mode_tag, NPOS_TAG,
            "signed profile must select NPoS"
        );
        let ConsensusGenesisModeParams::Npos(npos_profile) = &profile.params.mode else {
            panic!("signed profile must include NPoS parameters");
        };
        assert_eq!(
            npos_profile.min_self_bond, expected,
            "signed profile must use the post-topology NPoS snapshot"
        );
        let expected_validator_count = network.peers().len();
        let genesis = network.genesis();
        let mut validator_count = 0;
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    if let Some(register) = instruction
                        .as_any()
                        .downcast_ref::<RegisterPublicLaneValidator>()
                    {
                        validator_count += 1;
                        assert_eq!(
                            register.initial_stake, expected,
                            "every bootstrap validator must honor the post-topology min_self_bond"
                        );
                    }
                }
            }
        }
        assert_eq!(
            validator_count, expected_validator_count,
            "bootstrap must register every network peer as a validator"
        );
    }
    #[test]
    fn npos_bootstrap_overrides_stake_accounts_in_config() {
        let stake_amount = SumeragiNposParameters::default().min_self_bond().clone();
        let network = NetworkBuilder::new()
            .with_peers(4)
            .with_auto_populated_trusted_peers()
            .with_npos_genesis_bootstrap(stake_amount)
            .build();
        let mut merged = Table::new();
        for layer in network.config_layers() {
            merge_tables(&mut merged, layer.as_ref());
        }
        let stake_escrow =
            get_nested_value(&merged, &["nexus", "staking", "stake_escrow_account_id"])
                .and_then(Value::as_str)
                .expect("stake_escrow_account_id should be present");
        let slash_sink = get_nested_value(&merged, &["nexus", "staking", "slash_sink_account_id"])
            .and_then(Value::as_str)
            .expect("slash_sink_account_id should be present");
        assert!(
            AccountId::parse_encoded(stake_escrow).is_ok(),
            "stake_escrow_account_id must parse as AccountId; got {stake_escrow}"
        );
        assert!(
            AccountId::parse_encoded(slash_sink).is_ok(),
            "slash_sink_account_id must parse as AccountId; got {slash_sink}"
        );
    }
    #[test]
    fn npos_bootstrap_seeds_default_fee_asset_for_runtime_signers() {
        init_instruction_registry();
        let network = NetworkBuilder::new()
            .with_peers(4)
            .with_auto_populated_trusted_peers()
            .with_npos_consensus()
            .build();
        let genesis = network.genesis();
        let fee_asset_definition_id: AssetDefinitionId = defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("default nexus fee asset id");
        let first_validator_id = network
            .peers()
            .first()
            .expect("validator peer")
            .account_id();
        let mut definition_count = 0;
        let mut saw_staking_plan = false;
        let mut saw_alice_mint = false;
        let mut saw_validator_mint = false;
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    if let Some(register) = instruction
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::RegisterBox>()
                        && let iroha_data_model::isi::RegisterBox::AssetDefinition(register) =
                            register
                        && register.object.id == fee_asset_definition_id
                    {
                        definition_count += 1;
                        assert_eq!(&register.object.spec, &NumericSpec::fractional(9));
                    }
                    if let Some(registration) = instruction
                        .as_any()
                        .downcast_ref::<RegisterPublicLaneValidator>()
                    {
                        assert_eq!(
                            registration.monetary_plan.source_asset.definition(),
                            &fee_asset_definition_id
                        );
                        assert_eq!(
                            registration.monetary_plan.destination_asset.definition(),
                            &fee_asset_definition_id
                        );
                        saw_staking_plan = true;
                    }
                    if let Some(mint) = instruction
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::MintBox>()
                        && let iroha_data_model::isi::MintBox::Asset(mint) = mint
                        && mint.destination.definition() == &fee_asset_definition_id
                    {
                        if mint.destination.account() == &*ALICE_ID {
                            saw_alice_mint = true;
                        }
                        if mint.destination.account() == &first_validator_id {
                            saw_validator_mint = true;
                        }
                    }
                }
            }
        }
        assert_eq!(
            definition_count, 1,
            "staking and fees share exactly one XOR definition"
        );
        assert!(saw_staking_plan);
        assert!(
            saw_alice_mint,
            "npos bootstrap should fund ALICE with the default nexus fee asset"
        );
        assert!(
            saw_validator_mint,
            "npos bootstrap should fund validators with the default nexus fee asset"
        );
    }
    #[test]
    fn default_builder_grants_soracloud_management_to_validator_runtime_signers() {
        init_instruction_registry();
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_auto_populated_trusted_peers(),
        );
        let genesis = network.genesis();
        let validator_ids = network
            .peers()
            .iter()
            .map(NetworkPeer::account_id)
            .collect::<BTreeSet<_>>();
        let mut granted = BTreeSet::new();
        for tx in genesis.0.external_transactions() {
            if let Executable::Instructions(instructions) = tx.instructions() {
                for instruction in instructions {
                    let Some(grant) = instruction
                        .as_any()
                        .downcast_ref::<iroha_data_model::isi::GrantBox>()
                    else {
                        continue;
                    };
                    let iroha_data_model::isi::GrantBox::Permission(grant) = grant else {
                        continue;
                    };
                    if grant.object.name() == "CanManageSoracloud"
                        && validator_ids.contains(&grant.destination)
                    {
                        granted.insert(grant.destination.clone());
                    }
                }
            }
        }
        assert_eq!(
            granted, validator_ids,
            "default test-network genesis should grant CanManageSoracloud to validator runtime signers"
        );
    }
    #[test]
    fn default_builder_sets_parseable_nexus_account_literals() {
        let network = build_with_isolated_permit(NetworkBuilder::new());
        let mut merged = Table::new();
        for layer in network.config_layers() {
            merge_tables(&mut merged, layer.as_ref());
        }
        let fee_sink = get_nested_value(&merged, &["nexus", "fees", "fee_sink_account_id"])
            .and_then(Value::as_str)
            .expect("fee_sink_account_id should be present");
        let stake_escrow =
            get_nested_value(&merged, &["nexus", "staking", "stake_escrow_account_id"])
                .and_then(Value::as_str)
                .expect("stake_escrow_account_id should be present");
        let slash_sink = get_nested_value(&merged, &["nexus", "staking", "slash_sink_account_id"])
            .and_then(Value::as_str)
            .expect("slash_sink_account_id should be present");
        assert!(
            AccountId::parse_encoded(fee_sink).is_ok(),
            "fee_sink_account_id must parse as AccountId; got {fee_sink}"
        );
        assert!(
            AccountId::parse_encoded(stake_escrow).is_ok(),
            "stake_escrow_account_id must parse as AccountId; got {stake_escrow}"
        );
        assert!(
            AccountId::parse_encoded(slash_sink).is_ok(),
            "slash_sink_account_id must parse as AccountId; got {slash_sink}"
        );
    }
    #[test]
    fn default_builder_uses_localnet_block_cadence() {
        let network = build_with_isolated_permit(NetworkBuilder::new());
        assert_eq!(network.block_cadence(), LOCALNET_BLOCK_CADENCE);
        assert_eq!(
            network
                .consensus_bootstrap_profile()
                .params
                .block_cadence_ms
                .get(),
            LOCALNET_BLOCK_CADENCE.as_millis() as u64,
            "the localnet cadence must be carried by signed consensus metadata"
        );
    }
    #[test]
    fn default_block_cadence_matches_protocol_default() {
        init_instruction_registry();
        let expected_ms = defaults::sumeragi::BLOCK_CADENCE_MS;
        assert_eq!(expected_ms, 1_000, "fresh-network cadence must remain 1 s");
        let expected = Duration::from_millis(expected_ms);
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_default_block_cadence());
        assert_eq!(network.block_cadence(), expected);
        assert_eq!(
            network
                .consensus_bootstrap_profile()
                .params
                .block_cadence_ms
                .get(),
            expected_ms,
            "signed consensus profile must use the protocol cadence"
        );
        let metadata = consensus_handshake_metadata(&network.genesis())
            .expect("genesis must contain decodable consensus handshake metadata");
        assert_eq!(
            metadata.block_cadence_ms.get(),
            expected_ms,
            "handshake metadata must advertise the protocol cadence"
        );
    }
    #[test]
    fn explicit_block_cadence_sets_signed_metadata() {
        init_instruction_registry();
        let duration = Duration::from_secs(3);
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_block_cadence(duration));
        let genesis = network.genesis();
        let profile = network.consensus_bootstrap_profile();
        assert_eq!(network.block_cadence(), duration);
        assert_eq!(profile.params.block_cadence_ms.get(), 3_000);
        assert_exactly_one_consensus_handshake(&genesis, &consensus_handshake_parameter(&profile));
        assert_eq!(
            consensus_handshake_metadata(&genesis)
                .expect("genesis must contain canonical consensus metadata")
                .block_cadence_ms
                .get(),
            3_000,
            "signed handshake metadata must carry the explicit cadence"
        );
    }
    #[test]
    fn configured_block_cadence_reports_explicit_override() {
        let duration = Duration::from_secs(3);
        let builder = NetworkBuilder::new().with_block_cadence(duration);
        assert_eq!(builder.configured_block_cadence(), Some(duration));
        let default_builder = NetworkBuilder::new().with_default_block_cadence();
        assert_eq!(default_builder.configured_block_cadence(), None);
    }
    #[test]
    #[should_panic(expected = "block cadence must be at least 1 ms")]
    fn block_cadence_rejects_sub_millisecond_values() {
        let _ = NetworkBuilder::new().with_block_cadence(Duration::from_nanos(999_999));
    }
    #[test]
    #[should_panic(expected = "block cadence must not exceed")]
    fn block_cadence_rejects_values_that_do_not_fit_genesis() {
        let _ = NetworkBuilder::new().with_block_cadence(Duration::from_secs(u64::MAX));
    }
    #[test]
    fn block_sync_gossip_period_override_is_applied() {
        let period = Duration::from_millis(750);
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_block_sync_gossip_period(period));
        let mut layers = network.config_layers();
        let _trusted = layers.next().expect("trusted peers layer present");
        let base_layer = layers
            .next()
            .expect("base config layer present")
            .into_owned();
        let network_section = base_layer
            .get("network")
            .and_then(|value| value.as_table())
            .expect("network table present");
        let period_value = network_section
            .get("block_gossip_period_ms")
            .and_then(|value| value.as_integer())
            .expect("block gossip period as integer");
        let expected = i64::try_from(period.as_millis()).expect("fits in i64");
        assert_eq!(period_value, expected);
    }
    #[test]
    fn builder_sets_ivm_fuel() {
        let builder = NetworkBuilder::new().with_ivm_fuel(IvmFuelConfig::Unset);
        assert!(matches!(builder.ivm_fuel, IvmFuelConfig::Unset));
    }
    #[test]
    fn peer_builder_mnemonic_has_no_whitespace() {
        let builder = NetworkPeerBuilder::new();
        assert!(builder.mnemonic.chars().all(|c| !c.is_whitespace()));
    }
    #[test]
    fn checked_key_pair_from_seed_uses_checked_derivation() {
        assert_eq!(
            checked_key_pair_from_seed(vec![1; 32], Algorithm::Ed25519).algorithm(),
            Algorithm::Ed25519
        );
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    #[test]
    fn peer_id_uses_bls() {
        let env = Environment::new();
        let peer = NetworkPeerBuilder::new().build(&env);
        assert_eq!(
            peer.id()
                .public_key()
                .try_algorithm()
                .expect("fixture peer public key must be well-formed"),
            Algorithm::BlsNormal
        );
        assert_eq!(
            peer.account_id(),
            AccountId::new(peer.streaming_public_key().clone()),
            "runtime account identity should use the streaming key"
        );
        assert_eq!(
            peer.streaming_public_key()
                .try_algorithm()
                .expect("fixture streaming public key must be well-formed"),
            Algorithm::Ed25519,
            "streaming identity should remain Ed25519 even with BLS peers"
        );
        assert_eq!(
            peer.soranet_transport_public_key()
                .try_algorithm()
                .expect("fixture SoraNet transport public key must be well-formed"),
            Algorithm::Ed25519,
            "SoraNet transport identity must be Ed25519"
        );
        assert_ne!(
            peer.soranet_transport_public_key(),
            peer.streaming_public_key(),
            "SoraNet transport and streaming identities must be distinct"
        );
        assert!(
            peer.bls_public_key().is_some(),
            "expected BLS key material to remain available"
        );
    }
    #[test]
    fn base_config_sets_streaming_identity_keys() {
        let env = Environment::new();
        let peer = NetworkPeerBuilder::new().build(&env);
        let path = peer.dir.join("config.base.toml");
        let contents = std::fs::read_to_string(&path).expect("read base config");
        let table: toml::Table = toml::from_str(&contents).expect("parse base config");
        let streaming = table
            .get("streaming")
            .and_then(toml::Value::as_table)
            .expect("streaming table present");
        let identity_public = streaming
            .get("identity_public_key")
            .and_then(toml::Value::as_str)
            .expect("identity public key string");
        let parsed: iroha_crypto::PublicKey = identity_public.parse().expect("identity key parses");
        assert_eq!(
            parsed.algorithm(),
            Algorithm::Ed25519,
            "streaming identity must use Ed25519"
        );
        let identity_private = streaming
            .get("identity_private_key")
            .and_then(toml::Value::as_str)
            .expect("identity private key string");
        assert!(
            identity_private.starts_with("8026"),
            "private key should be hex-like multihash"
        );
        let transport_public = table
            .get("soranet_transport_public_key")
            .and_then(toml::Value::as_str)
            .expect("SoraNet transport public key string");
        let transport_public: PublicKey = transport_public
            .parse()
            .expect("SoraNet transport public key parses");
        assert_eq!(transport_public, *peer.soranet_transport_public_key());
        assert_eq!(transport_public.algorithm(), Algorithm::Ed25519);
        assert_ne!(transport_public, parsed);
        let transport_private = table
            .get("soranet_transport_private_key")
            .and_then(toml::Value::as_str)
            .expect("SoraNet transport private key string");
        assert!(
            transport_private.starts_with("8026"),
            "SoraNet transport private key should be hex-like multihash"
        );
        let transport_private: PrivateKey = transport_private
            .parse()
            .expect("SoraNet transport private key parses");
        let transport_pair = KeyPair::new(transport_public, transport_private)
            .expect("base config SoraNet transport key pair must match");
        assert_eq!(&transport_pair, peer.soranet_transport_key_pair());
    }
    #[test]
    fn seeded_peer_derives_domain_separated_soranet_transport_identity() {
        let seed = b"deterministic-peer-identity".to_vec();
        let expected = checked_soranet_transport_key_pair_from_seed(seed.clone());
        let raw_seed_identity = checked_key_pair_from_seed(seed.clone(), Algorithm::Ed25519);
        let first_env = Environment::new();
        let first = NetworkPeerBuilder::new()
            .with_seed(Some(seed.clone()))
            .build(&first_env);
        let second_env = Environment::new();
        let second = NetworkPeerBuilder::new()
            .with_seed(Some(seed))
            .build(&second_env);
        assert_eq!(first.soranet_transport_key_pair(), &expected);
        assert_eq!(second.soranet_transport_key_pair(), &expected);
        assert_ne!(
            first.soranet_transport_public_key(),
            raw_seed_identity.public_key(),
            "transport derivation must never consume the raw streaming seed"
        );
        assert_eq!(P2P_SORANET_TRANSPORT_SEED_DOMAIN, b":p2p-soranet-transport");
    }
    #[test]
    fn uses_shared_instruction_registry() {
        init_instruction_registry();
        let instruction = RegisterBox::Domain(Register::domain(Domain::new(
            DomainId::try_new("test", "universal").unwrap(),
        )));
        let instruction_box: InstructionBox = instruction.into();
        let bytes = norito::to_bytes(&instruction_box).expect("encode");
        let decoded: InstructionBox = norito::decode_from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, instruction_box);
    }
    #[test]
    fn program_absolute_prebuilt_override_does_not_require_checkout() {
        let _guard = lock_env_guard(&PROGRAM_BIN_ENV_GUARD);
        let _clear_source = EnvVarGuard::cleared(IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV);
        let _clear_prebuilt = EnvVarGuard::cleared(IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV);
        let fixture = tempdir().expect("temporary missing repository fixture");
        let missing_repo = fixture.path().join("missing-checkout");
        let binary = env::current_exe().expect("current prebuilt test binary");
        let _binary = EnvVarRestore::set(PROGRAM_IROHA_ENV, &binary);
        let resolved = Program::Iroha
            .resolve_internal_in_repo(Some(true), &missing_repo)
            .expect("absolute diagnostic binary must not need its build checkout");
        assert_eq!(
            resolved,
            binary.canonicalize().expect("canonical test binary")
        );
        assert!(release_program_contract(&missing_repo).unwrap().is_none());
        assert!(
            resolve_release_prebuilt_binary(ReleasePrebuiltBinary::Iroha)
                .expect("inactive release lookup must not need a checkout")
                .is_none()
        );
        assert!(
            revalidate_release_prebuilt_binary(ReleasePrebuiltBinary::Iroha, &binary)
                .expect("inactive release revalidation must not need a checkout")
                .is_none()
        );
        assert!(!missing_repo.exists());
    }
    #[test]
    fn program_discovery_requires_checkout_with_context() {
        let _guard = lock_env_guard(&PROGRAM_BIN_ENV_GUARD);
        let _clear_source = EnvVarGuard::cleared(IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV);
        let _clear_prebuilt = EnvVarGuard::cleared(IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV);
        let _clear_binary = EnvVarGuard::cleared(PROGRAM_IROHA_ENV);
        let fixture = tempdir().expect("temporary missing repository fixture");
        let missing_repo = fixture.path().join("missing-checkout");
        for skip_build in [true, false] {
            let error = Program::Iroha
                .resolve_internal_in_repo(Some(skip_build), &missing_repo)
                .expect_err("discovery and builds must require the real checkout");
            let message = error.to_string();
            assert!(message.contains("Could not access repository"), "{message}");
            assert!(message.contains(PROGRAM_IROHA_ENV), "{message}");
            assert!(
                message.contains(&missing_repo.display().to_string()),
                "{message}"
            );
        }
        let _relative = EnvVarRestore::set(PROGRAM_IROHA_ENV, "target/release/iroha");
        assert!(
            Program::Iroha
                .resolve_internal_in_repo(Some(true), &missing_repo)
                .is_err(),
            "a relative override must not become relative to an unrelated working directory"
        );
        assert!(!missing_repo.exists());
    }
    #[test]
    fn program_absolute_prebuilt_override_rejects_partial_release_identity() {
        let _guard = lock_env_guard(&PROGRAM_BIN_ENV_GUARD);
        let _clear_source = EnvVarGuard::cleared(IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV);
        let _clear_prebuilt = EnvVarGuard::cleared(IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV);
        let fixture = tempdir().expect("temporary missing repository fixture");
        let missing_repo = fixture.path().join("missing-checkout");
        let binary = env::current_exe().expect("current prebuilt test binary");
        let _binary = EnvVarRestore::set(PROGRAM_IROHA_ENV, &binary);
        for (present, required) in [
            (
                IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV,
                IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV,
            ),
            (
                IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV,
                IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV,
            ),
        ] {
            let _partial = EnvVarRestore::set(present, "a".repeat(64));
            let error = Program::Iroha
                .resolve_internal_in_repo(Some(true), &missing_repo)
                .expect_err("an absolute override must not bypass a partial release identity");
            assert!(error.to_string().contains(required), "{error}");
        }
        assert!(!missing_repo.exists());
    }
    #[test]
    fn program_absolute_prebuilt_override_requires_active_release_checkout() {
        let _guard = lock_env_guard(&PROGRAM_BIN_ENV_GUARD);
        let fixture = create_release_prebuilt_fixture();
        let _env = release_prebuilt_env(&fixture, &fixture.manifest_sha256);
        let binary = fixture
            .target
            .join(ReleasePrebuiltBinary::Iroha.relative_path());
        let _binary = EnvVarRestore::set(PROGRAM_IROHA_ENV, &binary);
        let missing_repo = fixture.repo.join("missing-checkout");
        let error = Program::Iroha
            .resolve_internal_in_repo(Some(true), &missing_repo)
            .expect_err("an active release contract must authenticate its real repository");
        assert!(
            error
                .to_string()
                .contains("failed to canonicalize repository root for release artifact isolation"),
            "{error}"
        );
        assert!(!missing_repo.exists());
    }
    #[test]
    fn program_resolve_uses_env_override_without_build() {
        let _guard = lock_env_guard(&PROGRAM_BIN_ENV_GUARD);
        let _clear_release = EnvVarGuard::cleared(IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV);
        let _clear_prebuilt = EnvVarGuard::cleared(IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV);
        let repo = tempfile::tempdir().expect("create isolated repository fixture");
        let rel = PathBuf::from("target/test-bin-dummy/iroha-cli-dummy");
        let abs = repo.path().join(&rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, b"dummy").unwrap();
        let old_env = env::var(super::PROGRAM_IROHA_ENV).ok();
        set_env_var(super::PROGRAM_IROHA_ENV, rel.display().to_string());
        // Should resolve to the dummy file via env override
        let resolved = Program::Iroha
            .resolve_internal_in_repo(Some(true), repo.path())
            .expect("resolve via env");
        assert_eq!(resolved, abs.canonicalize().unwrap());
        // Cleanup and restore environment
        if let Some(v) = old_env {
            set_env_var(super::PROGRAM_IROHA_ENV, v);
        } else {
            remove_env_var(super::PROGRAM_IROHA_ENV);
        }
    }
    #[tokio::test]
    async fn program_resolve_async_honors_env_override() {
        let _guard = lock_env_guard_async(&PROGRAM_BIN_ENV_GUARD).await;
        let _clear_release = EnvVarGuard::cleared(IROHA_RELEASE_SOURCE_MANIFEST_SHA256_ENV);
        let _clear_prebuilt = EnvVarGuard::cleared(IROHA_RELEASE_PREBUILT_MANIFEST_SHA256_ENV);
        let fixture = tempfile::tempdir().expect("create isolated executable fixture");
        let abs = fixture.path().join("iroha-cli-dummy-async");
        std::fs::write(&abs, b"dummy").unwrap();
        let old_env = env::var(super::PROGRAM_IROHA_ENV).ok();
        set_env_var(super::PROGRAM_IROHA_ENV, abs.display().to_string());
        let resolved = Program::Iroha
            .resolve_async()
            .await
            .expect("resolve via env");
        assert_eq!(resolved, abs.canonicalize().unwrap());
        if let Some(v) = old_env {
            set_env_var(super::PROGRAM_IROHA_ENV, v);
        } else {
            remove_env_var(super::PROGRAM_IROHA_ENV);
        }
    }
    #[test]
    fn cached_binary_if_present_returns_existing_path() {
        let cache = OnceLock::new();
        let current_exe = env::current_exe().expect("current test binary path");
        cache
            .set(current_exe.clone())
            .expect("cache should be empty for test");
        assert_eq!(cached_binary_if_present(&cache), Some(current_exe));
    }
    #[test]
    fn cached_binary_if_present_ignores_missing_path() {
        let cache = OnceLock::new();
        let fixture = tempfile::tempdir().expect("create isolated missing executable fixture");
        let missing = fixture.path().join("missing-iroha3d");
        cache.set(missing).expect("cache should be empty for test");
        assert!(cached_binary_if_present(&cache).is_none());
    }
    #[test]
    fn program_spec_irohad_uses_default_features() {
        let spec = Program::Irohad.spec();
        let args: Vec<String> = spec
            .build_args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert!(args.contains(&"--bin".to_string()));
        assert!(args.contains(&"iroha3d".to_string()));
        assert!(!args.contains(&"--features".to_string()));
        assert!(spec.isolated_target_subdir.is_none());
        assert_ne!(spec.env, PROGRAM_IROHAD_PRIVATE_SETTLEMENT_ROUTES_ENV);
    }
    #[test]
    fn private_settlement_route_daemon_is_feature_and_target_isolated() {
        let spec = Program::IrohadPrivateSettlementRoutes.spec();
        let args = spec
            .build_args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(spec.env, PROGRAM_IROHAD_PRIVATE_SETTLEMENT_ROUTES_ENV);
        assert_eq!(
            spec.isolated_target_subdir,
            Some("private-settlement-route-control")
        );
        assert!(args.windows(2).any(|pair| {
            pair == [
                "--features",
                "test-network-private-settlement-route-control",
            ]
        }));
        assert!(!Program::IrohadPrivateSettlementRoutes.release_prebuilt_allowed());
    }
    #[test]
    fn disposable_broker_is_feature_target_and_release_isolated() {
        let spec = Program::IrohadDisposableBroker.spec();
        let args = spec
            .build_args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(spec.env, "TEST_NETWORK_BIN_IROHAD_DISPOSABLE_BROKER");
        assert_eq!(spec.isolated_target_subdir, Some("disposable-broker"));
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--bin", "iroha_test_runtime_provider_broker"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--features", "test-network-disposable-broker"] })
        );
        assert!(!Program::IrohadDisposableBroker.release_prebuilt_allowed());
    }
    #[test]
    fn parliament_signer_daemon_is_feature_target_and_release_isolated() {
        let spec = Program::IrohadParliamentSigners.spec();
        let args = spec
            .build_args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(spec.env, PROGRAM_IROHAD_PARLIAMENT_SIGNERS_ENV);
        assert_eq!(spec.isolated_target_subdir, Some("parliament-signers"));
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--features", "test-network-parliament-signers"] })
        );
        assert!(!Program::IrohadParliamentSigners.release_prebuilt_allowed());

        let daemon_manifest = include_str!("../../irohad/Cargo.toml");
        let default_feature = daemon_manifest
            .split_once("default = [")
            .and_then(|(_, tail)| tail.split_once(']'))
            .map(|(value, _)| value)
            .expect("irohad default feature declaration");
        let daemon_feature = daemon_manifest
            .split_once("daemon = [")
            .and_then(|(_, tail)| tail.split_once(']'))
            .map(|(value, _)| value)
            .expect("irohad daemon feature declaration");
        for shipping_feature in [default_feature, daemon_feature] {
            assert!(
                !shipping_feature.contains("test-network-parliament-signers"),
                "ordinary daemon construction must not compile the test signer"
            );
        }
        let core_manifest = include_str!("../../iroha_core/Cargo.toml");
        let core_default_feature = core_manifest
            .split_once("default = [")
            .and_then(|(_, tail)| tail.split_once(']'))
            .map(|(value, _)| value)
            .expect("iroha_core default feature declaration");
        let core_node_feature = core_manifest
            .split_once("node = [")
            .and_then(|(_, tail)| tail.split_once(']'))
            .map(|(value, _)| value)
            .expect("iroha_core node feature declaration");
        for shipping_feature in [core_default_feature, core_node_feature] {
            assert!(
                !shipping_feature.contains("test-network-parliament-signers"),
                "ordinary Core construction must not compile the test signer"
            );
        }
        let integration_manifest = include_str!("../../../integration_tests/Cargo.toml");
        assert!(integration_manifest.contains("required-features = [\"parliament-test-signers\"]"));
        assert!(integration_manifest.contains(
            "parliament-test-signers = [\"iroha_core/test-network-parliament-signers\"]"
        ));
        let daemon_source = include_str!("../../irohad/src/main.rs");
        assert!(daemon_source.contains("not(debug_assertions)"));
        assert!(daemon_source.contains(
            "the feature-isolated Parliament fixture signers cannot be compiled into an optimized daemon"
        ));

        let beacon_provider =
            include_str!("../../iroha_core/src/beacon/parliament_test_network_signer.rs");
        let tle_provider =
            include_str!("../../iroha_core/src/tle_release/parliament_test_network_signer.rs");
        assert!(beacon_provider.contains("GlobalThresholdBeaconPartialSignerV1"));
        assert!(tle_provider.contains("TlePartialReleaseSignerV1"));
        for provider in [beacon_provider, tle_provider] {
            assert!(
                provider.contains("#[cfg(not(debug_assertions))]"),
                "the Core provider itself must reject optimized compilation"
            );
            for forbidden in [
                "FinalizedGlobalThresholdBeaconPulseV1",
                "TleFinalReleaseSignatureV1",
                "ParliamentLifecycleTransitionV1",
                "StateTransaction",
                "put_parliament_attempt",
            ] {
                assert!(
                    !provider.contains(forbidden),
                    "test signer providers must return partial shares only, not `{forbidden}`"
                );
            }
        }
    }
    #[test]
    fn parliament_beacon_signer_modes_are_exact_and_restart_stable() {
        let modes = [
            ParliamentBeaconSignerMode::Valid,
            ParliamentBeaconSignerMode::Valid,
            ParliamentBeaconSignerMode::Absent,
            ParliamentBeaconSignerMode::Invalid,
        ];
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_parliament_beacon_signer_modes(modes),
        );
        assert_eq!(network.peers().len(), modes.len());

        for (peer, expected) in network.peers().iter().zip(modes) {
            assert_eq!(peer.parliament_beacon_signer_mode, Some(expected));
            let child_args = |peer: &NetworkPeer| {
                let mut command = tokio::process::Command::new("iroha3d");
                peer.append_parliament_beacon_signer_mode_arg(&mut command);
                command
                    .as_std()
                    .get_args()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            };
            let first_run = child_args(peer);
            assert_eq!(
                first_run,
                vec![
                    PARLIAMENT_BEACON_SIGNER_MODE_ARG.to_owned(),
                    expected.child_arg().to_owned(),
                ],
            );
            peer.runs_count.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                child_args(peer),
                first_run,
                "a normal peer restart must preserve its exact child-only signer mode",
            );
        }
    }
    #[test]
    fn parliament_beacon_signer_modes_require_one_entry_per_validator() {
        let too_short = std::panic::catch_unwind(|| {
            NetworkBuilder::new()
                .with_peers(4)
                .with_parliament_beacon_signer_modes([
                    ParliamentBeaconSignerMode::Valid,
                    ParliamentBeaconSignerMode::Absent,
                    ParliamentBeaconSignerMode::Invalid,
                ])
        });
        assert!(too_short.is_err());

        let exact = NetworkBuilder::new()
            .with_peers(4)
            .with_parliament_beacon_signer_modes([
                ParliamentBeaconSignerMode::Valid,
                ParliamentBeaconSignerMode::Valid,
                ParliamentBeaconSignerMode::Absent,
                ParliamentBeaconSignerMode::Invalid,
            ]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exact.with_peers(7))).is_err()
        );

        let all_valid = NetworkBuilder::new()
            .with_peers(PARLIAMENT_TEST_SIGNER_VALIDATOR_COUNT)
            .with_parliament_test_signers();
        assert_eq!(
            all_valid
                .parliament_test_signers
                .as_ref()
                .expect("all-valid shorthand remains selected")
                .resolve(PARLIAMENT_TEST_SIGNER_VALIDATOR_COUNT),
            vec![ParliamentBeaconSignerMode::Valid; PARLIAMENT_TEST_SIGNER_VALIDATOR_COUNT],
        );
        assert!(
            std::panic::catch_unwind(|| {
                NetworkBuilder::new()
                    .with_peers(7)
                    .with_parliament_test_signers()
            })
            .is_err(),
            "selecting the all-valid fixture after a seven-validator committee must fail early",
        );
        assert!(
            std::panic::catch_unwind(|| {
                NetworkBuilder::new()
                    .with_parliament_test_signers()
                    .with_peers(7)
            })
            .is_err(),
            "changing an all-valid fixture to seven validators must fail early",
        );
        assert!(
            std::panic::catch_unwind(|| {
                NetworkBuilder::new()
                    .with_parliament_test_signers()
                    .with_min_peers(5)
            })
            .is_err(),
            "raising an installed Parliament fixture above four validators must fail early",
        );
        assert!(
            std::panic::catch_unwind(|| {
                NetworkBuilder::new()
                    .with_min_peers(5)
                    .with_parliament_test_signers()
            })
            .is_err(),
            "selecting the Parliament fixture after a larger minimum must fail early",
        );
    }
    #[test]
    fn program_spec_irohad_includes_features_from_env() {
        let _guard = lock_env_guard(&PROGRAM_BIN_ENV_GUARD);
        let old_env = env::var(super::PROGRAM_IROHAD_FEATURES_ENV).ok();
        set_env_var(super::PROGRAM_IROHAD_FEATURES_ENV, "zk-stark");
        let spec = Program::Irohad.spec();
        let args: Vec<String> = spec
            .build_args
            .iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert!(args.contains(&"--features".to_string()));
        assert!(args.contains(&"zk-stark".to_string()));
        if let Some(v) = old_env {
            set_env_var(super::PROGRAM_IROHAD_FEATURES_ENV, v);
        } else {
            remove_env_var(super::PROGRAM_IROHAD_FEATURES_ENV);
        }
    }
    pub(super) fn build_with_isolated_permit(builder: NetworkBuilder) -> Network {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let dir = tempdir().expect("permit dir");
        let _dir_guard = EnvVarRestore::set(NETWORK_PERMIT_DIR_ENV, dir.path());
        let _parallel_guard = EnvVarRestore::set(NETWORK_PARALLELISM_ENV, "1");
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "0");
        builder.build()
    }
    pub(super) fn build_blocking_with_isolated_permit(
        builder: NetworkBuilder,
    ) -> (Network, Runtime) {
        let _guard = lock_env_guard(&NETWORK_PERMIT_ENV_GUARD);
        let dir = tempdir().expect("permit dir");
        let _dir_guard = EnvVarRestore::set(NETWORK_PERMIT_DIR_ENV, dir.path());
        let _parallel_guard = EnvVarRestore::set(NETWORK_PARALLELISM_ENV, "1");
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "0");
        builder.build_blocking()
    }
    async fn build_with_isolated_permit_async(builder: NetworkBuilder) -> Network {
        let _guard = lock_env_guard_async(&NETWORK_PERMIT_ENV_GUARD).await;
        let dir = tempdir().expect("permit dir");
        let _dir_guard = EnvVarRestore::set(NETWORK_PERMIT_DIR_ENV, dir.path());
        let _parallel_guard = EnvVarRestore::set(NETWORK_PARALLELISM_ENV, "1");
        let _serialize_guard = EnvVarRestore::set(SERIALIZE_NETWORKS_ENV, "0");
        builder.build()
    }
    #[test]
    fn torii_url_uses_api_port() {
        let network = build_with_isolated_permit(NetworkBuilder::new());
        let peer = network.peer();
        let url = peer.torii_url();
        assert!(url.starts_with("http://127.0.0.1:"));
        let port_str = url.rsplit(':').next().expect("url has a port");
        let port: u16 = port_str.parse().expect("port is u16");
        assert_eq!(port, peer.api_address().port());
    }
    #[test]
    fn network_torii_urls_match_peers() {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let urls = network.torii_urls();
        assert_eq!(urls.len(), network.peers().len());
        for (peer, url) in network.peers().iter().zip(urls.iter()) {
            assert!(url.starts_with("http://127.0.0.1:"));
            let port_str = url.rsplit(':').next().unwrap();
            let port: u16 = port_str.parse().unwrap();
            assert_eq!(port, peer.api_address().port());
        }
    }
    #[test]
    fn network_peer_round_robins_deterministically() {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let peers = network.peers();
        let expected = [
            peers[0].api_address(),
            peers[1].api_address(),
            peers[2].api_address(),
            peers[3].api_address(),
        ];
        let actual = [
            network.peer().api_address(),
            network.peer().api_address(),
            network.peer().api_address(),
            network.peer().api_address(),
        ];
        assert_eq!(actual, expected);
    }
    #[test]
    fn network_client_uses_first_peer() {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let expected = network
            .peers()
            .first()
            .expect("network has peers")
            .api_address();
        let client = network.client();
        let async_client = client.client();
        let expected_host = expected.host_str();
        assert_eq!(*async_client.network_id(), network.network_id());
        assert_eq!(
            async_client.endpoint().host_str(),
            Some(expected_host.as_ref())
        );
        assert_eq!(
            async_client.endpoint().port_or_known_default(),
            Some(expected.port())
        );
    }
    #[test]
    fn peer_async_client_factory_preserves_account_operator_and_configuration() {
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let peer = &network.peers()[0];
        let private_key = iroha_test_samples::BOB_KEYPAIR.private_key().clone();
        let client = peer.async_client_for(&BOB_ID, private_key.clone());
        let blocking = peer.client_for(&BOB_ID, private_key);
        let config = client.to_builder();
        assert_eq!(config.account, *BOB_ID);
        assert_eq!(
            config.key_pair.public_key(),
            BOB_ID.expect_single_signatory()
        );
        assert_eq!(config.operator_key_pair.as_ref(), Some(&peer.key_pair));
        assert_eq!(config.network_id, network.network_id());
        assert_eq!(config.chain, config::chain_id());
        assert_eq!(
            config.torii_url,
            peer.torii_url()
                .parse::<url::Url>()
                .expect("valid peer endpoint")
        );
        assert_eq!(
            config.transaction_status_timeout,
            client_status_timeout_env()
        );
        assert_eq!(config.torii_request_timeout, client_request_timeout_env());
        assert_eq!(
            config.transaction_ttl,
            Some(client_ttl_env(config.transaction_status_timeout))
        );
        assert_eq!(blocking.client().account(), client.account());
        assert_eq!(blocking.client().key_pair(), client.key_pair());
        assert_eq!(
            blocking.client().operator_key_pair(),
            client.operator_key_pair()
        );
        assert_eq!(blocking.client().network_id(), client.network_id());
        assert_eq!(blocking.client().endpoint(), client.endpoint());
    }
    #[test]
    fn http_start_gate_requires_http_source() {
        let mut gate = HttpStartGate::default();
        assert!(!gate.http_seen(), "gate starts without HTTP observations");
        assert!(!gate.on_status(StatusSource::Storage));
        assert!(!gate.http_seen(), "storage status must not flip readiness");
        assert!(gate.on_status(StatusSource::Http));
        assert!(gate.http_seen(), "first HTTP status should trip readiness");
        assert!(
            !gate.on_status(StatusSource::Http),
            "subsequent HTTP statuses should not retrigger"
        );
    }
    #[test]
    fn genesis_is_cached_and_deterministic() {
        // Repeated calls to `Network::genesis()` must return the exact same block
        // so that multiple peers submitting genesis use identical bytes.
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let g1 = network.genesis();
        let g2 = network.genesis();
        // Compare encoded bytes to be strict about byte-for-byte equality
        let b1 = g1.0.encode_versioned();
        let b2 = g2.0.encode_versioned();
        assert_eq!(b1, b2, "genesis must be identical across calls");
        let f1 = g1.0.encode_wire().expect("encode genesis wire");
        let f2 = g2.0.encode_wire().expect("encode genesis wire");
        assert_eq!(f1, f2, "framed genesis must be identical across calls");
    }
    #[test]
    fn retained_genesis_manifest_is_bound_to_exact_signed_wire() {
        init_instruction_registry();
        let network = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
        let bundle = network
            .native_genesis_provisioning_bundle()
            .expect("generated genesis retains its original manifest");
        assert_eq!(sha256(&bundle.manifest_json), bundle.manifest_sha256);
        assert_eq!(network.genesis().0.hash(), bundle.block_hash);
        assert_eq!(
            network.genesis().0.encode_wire().expect("genesis wire"),
            bundle.signed_wire
        );
        let tampered = {
            let mut bytes = bundle.signed_wire.clone();
            let last = bytes.last_mut().expect("nonempty signed genesis");
            *last ^= 1;
            bytes
        };
        let manifest: RawGenesisTransaction =
            norito::json::from_slice(&bundle.manifest_json).expect("raw manifest roundtrip");
        assert!(
            iroha_genesis::validate_prepared_genesis_bundle(
                &tampered,
                &manifest,
                &bundle.public_key,
                bundle.block_hash,
            )
            .is_err(),
            "a changed signed block cannot reuse the retained manifest identity"
        );
    }
    #[test]
    fn genesis_roundtrip_decodes() {
        init_instruction_registry();
        let network = NetworkBuilder::new().build();
        let block = network.genesis();
        let versioned = block.0.encode_versioned();
        let framed = block.0.encode_wire().expect("encode versioned genesis");
        if let Ok(dump_path) = env::var("IROHA_TEST_DUMP_GENESIS") {
            let dump_path = std::path::PathBuf::from(dump_path);
            if let Some(parent) = dump_path.parent() {
                std::fs::create_dir_all(parent).expect("create dump directory");
            }
            std::fs::write(&dump_path, &framed).expect("write genesis dump");
        }
        assert!(
            !framed.is_empty(),
            "versioned encoding includes at least a version byte"
        );
        let (_, payload) = framed
            .split_first()
            .expect("versioned payload has a prefix");
        assert!(
            payload.starts_with(norito::core::MAGIC.as_slice()),
            "payload must start with Norito magic header"
        );
        let header_index = 1 + norito::core::Header::SIZE - 1;
        assert_eq!(
            framed[header_index],
            norito::core::default_encode_flags(),
            "framed genesis must use canonical header flags",
        );
        let deframed =
            deframe_versioned_signed_block_bytes(&framed).expect("deframe framed genesis");
        assert_eq!(deframed.bytes.as_ref(), framed.as_slice());
        assert_eq!(deframed.bare_versioned.as_ref(), versioned.as_slice());
        let decoded = decode_framed_signed_block(framed.as_slice()).expect("decode framed genesis");
        assert_eq!(
            decoded.version(),
            1,
            "decoded genesis must be a version 1 signed block"
        );
        assert_eq!(
            decoded.header(),
            block.0.header(),
            "canonical genesis wire must preserve the exact signed header",
        );
        assert_eq!(
            decoded.hash(),
            block.0.hash(),
            "canonical genesis wire must preserve the configured trust-anchor hash",
        );
    }
    #[test]
    fn with_genesis_block_uses_custom_builder() {
        init_instruction_registry();
        let seen_topology: Arc<Mutex<Option<UniqueVec<PeerId>>>> = Arc::new(Mutex::new(None));
        let seen_pops: Arc<Mutex<Option<Vec<GenesisTopologyEntry>>>> = Arc::new(Mutex::new(None));
        let callback_topology = Arc::clone(&seen_topology);
        let callback_pops = Arc::clone(&seen_pops);
        let network =
            build_with_isolated_permit(NetworkBuilder::new().with_peers(4).with_genesis_block(
                move |topology, pops| {
                    *callback_topology
                        .lock()
                        .expect("callback topology mutex poisoned") = Some(topology.clone());
                    *callback_pops.lock().expect("callback pop mutex poisoned") =
                        Some(pops.clone());
                    unexecuted_genesis_factory_with_post_topology(
                        Vec::new(),
                        Vec::new(),
                        topology,
                        pops,
                    )
                },
            ));
        let produced = network.genesis();
        assert!(
            produced.0.has_results(),
            "NetworkBuilder must prepare an unexecuted custom genesis"
        );
        let recorded = seen_topology
            .lock()
            .expect("topology mutex poisoned")
            .clone()
            .expect("topology should be recorded");
        let recorded_pops = seen_pops
            .lock()
            .expect("pop mutex poisoned")
            .clone()
            .expect("topology pops should be recorded");
        let expected = unexecuted_genesis_factory_with_post_topology(
            Vec::new(),
            Vec::new(),
            recorded,
            recorded_pops,
        );
        assert!(
            !expected.0.has_results(),
            "the custom-genesis helper must defer transaction execution"
        );
        // Canonical parameters are consolidated ahead of ordinary instructions;
        // the custom builder still owns the exact ordinary instruction sequence.
        let produced_instructions = collect_non_parameter_instructions(&produced);
        let expected_instructions = collect_non_parameter_instructions(&expected);
        assert_eq!(
            produced_instructions, expected_instructions,
            "custom genesis builder must preserve every ordinary instruction in order"
        );
        let expected_handshake = consensus_handshake_parameter(&network.consensus_profile);
        assert_exactly_one_consensus_handshake(&produced, &expected_handshake);
    }
    #[test]
    fn observer_aware_custom_genesis_keeps_observers_out_of_voting_roster() {
        init_instruction_registry();
        let seen_topology: Arc<Mutex<Option<UniqueVec<PeerId>>>> = Arc::new(Mutex::new(None));
        let seen_observers: Arc<Mutex<Option<Vec<PeerId>>>> = Arc::new(Mutex::new(None));
        let callback_topology = Arc::clone(&seen_topology);
        let callback_observers = Arc::clone(&seen_observers);
        let builder = NetworkBuilder::new()
            .with_peers(4)
            .with_observer_p2p_bootstrap(
                ObserverP2pBootstrap::new(4).expect("valid observer count"),
            )
            .expect("four validators and four observers fit the P2P capacity")
            .with_genesis_block_and_observers(move |topology, pops, observers| {
                *callback_topology
                    .lock()
                    .expect("callback topology mutex poisoned") = Some(topology.clone());
                *callback_observers
                    .lock()
                    .expect("callback observers mutex poisoned") = Some(observers);
                unexecuted_genesis_factory_with_post_topology(
                    Vec::new(),
                    Vec::new(),
                    topology,
                    pops,
                )
            });
        let network = build_with_isolated_permit(builder);
        let recorded_topology = seen_topology
            .lock()
            .expect("topology mutex poisoned")
            .clone()
            .expect("voting topology should be recorded");
        let recorded_observers = seen_observers
            .lock()
            .expect("observer mutex poisoned")
            .clone()
            .expect("observer identities should be recorded");
        let expected_validators = network
            .validators()
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        let expected_observers = network
            .observers()
            .iter()
            .map(NetworkPeer::id)
            .collect::<Vec<_>>();
        assert_eq!(
            recorded_topology.into_iter().collect::<Vec<_>>(),
            expected_validators
        );
        assert_eq!(recorded_observers, expected_observers);
        assert!(
            expected_validators
                .iter()
                .all(|validator| !expected_observers.contains(validator)),
            "voting validators and signed observers must be disjoint"
        );
        let observer_layers = network
            .config_layers_for_peer(&network.observers()[0])
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        assert_eq!(
            observer_layers
                .last()
                .and_then(|layer| get_nested_value(layer, &["sumeragi", "role"]))
                .and_then(Value::as_str),
            Some("observer"),
            "peer-specific restart layers must preserve the non-voting observer role"
        );
        assert_eq!(
            genesis_committee_peers(&network.genesis().0)
                .expect("custom genesis voting roster")
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected_validators.into_iter().collect::<BTreeSet<_>>(),
            "observer-aware custom genesis must retain exactly four global voters"
        );
    }
    #[test]
    fn committee_validator_custom_genesis_keeps_exact_global_voting_roster() {
        init_instruction_registry();
        let seen_entries: Arc<Mutex<Option<Vec<GenesisTopologyEntry>>>> =
            Arc::new(Mutex::new(None));
        let callback_entries = Arc::clone(&seen_entries);
        let builder = NetworkBuilder::new()
            .with_peers(4)
            .with_committee_validator_p2p_bootstrap(
                CommitteeValidatorP2pBootstrap::new(4).expect("valid committee-validator count"),
            )
            .expect("four global and four committee validators fit the P2P capacity")
            .with_genesis_block_and_committee_validator_entries(
                move |topology, pops, committee_entries| {
                    let registrations = committee_entries
                        .iter()
                        .map(|entry| {
                            let pop = entry
                                .pop_bytes()
                                .expect("committee-validator PoP hex must decode")
                                .expect("committee-validator entry must carry a PoP");
                            InstructionBox::from(
                                iroha_data_model::isi::register::RegisterCommitteePeerWithPop::new(
                                    entry.peer.clone(),
                                    pop,
                                ),
                            )
                        })
                        .collect::<Vec<_>>();
                    *callback_entries
                        .lock()
                        .expect("callback entries mutex poisoned") = Some(committee_entries);
                    unexecuted_genesis_factory_with_post_topology(
                        Vec::new(),
                        vec![registrations],
                        topology,
                        pops,
                    )
                },
            );
        let network = build_with_isolated_permit(builder);
        let recorded_entries = seen_entries
            .lock()
            .expect("committee entries mutex poisoned")
            .clone()
            .expect("committee-validator entries should be recorded");
        let expected_entries = network
            .committee_validators()
            .iter()
            .map(|peer| peer.genesis_pop().expect("committee validator PoP"))
            .collect::<Vec<_>>();
        assert_eq!(recorded_entries, expected_entries);
        let committee_registration_count = network
            .genesis()
            .0
            .external_transactions()
            .filter_map(|transaction| match transaction.instructions() {
                Executable::Instructions(instructions) => Some(instructions),
                _ => None,
            })
            .flat_map(|instructions| instructions.iter())
            .filter(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<iroha_data_model::isi::register::RegisterCommitteePeerWithPop>()
                    .is_some()
            })
            .count();
        assert_eq!(
            committee_registration_count,
            expected_entries.len(),
            "custom genesis must retain every proof-bound Committee registration"
        );

        let expected_global = network
            .validators()
            .iter()
            .map(NetworkPeer::id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            genesis_committee_peers(&network.genesis().0)
                .expect("custom genesis voting roster")
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected_global,
            "supplementary committee validators must not widen the global voting roster"
        );
    }
    #[test]
    #[should_panic(
        expected = "signed test-network genesis voting roster must exactly match the guarded validator topology"
    )]
    fn with_genesis_block_rejects_a_different_signed_voting_roster() {
        init_instruction_registry();
        let _ = build_with_isolated_permit(NetworkBuilder::new().with_peers(4).with_genesis_block(
            |mut topology, mut topology_entries| {
                for index in 0..3 {
                    let key_pair = checked_key_pair_from_seed(
                        format!("foreign-custom-genesis-voter-{index}"),
                        Algorithm::BlsNormal,
                    );
                    let peer = PeerId::new(key_pair.public_key().clone());
                    let pop = iroha_crypto::bls_normal_pop_prove(key_pair.private_key())
                        .expect("derive foreign custom-genesis voter PoP");
                    let _ = topology.push(peer.clone());
                    topology_entries.push(GenesisTopologyEntry::new(peer, pop));
                }
                genesis_factory(Vec::new(), topology, topology_entries)
            },
        ));
    }
    include!("genesis_lane_policy_tests.rs");

    #[test]
    fn custom_genesis_binds_active_validator_projection_instead_of_normal_preview() {
        init_instruction_registry();
        const SEED: &str = "custom-genesis-active-validator-projection";
        fn fixture_stake_asset_id() -> AssetDefinitionId {
            SumeragiNposParameters::default().xor_asset_definition_id
        }
        fn fixture_escrow_id() -> AccountId {
            AccountId::new(
                checked_key_pair_from_seed(
                    format!("{SEED}-staking-custody").into_bytes(),
                    Algorithm::Ed25519,
                )
                .public_key()
                .clone(),
            )
        }

        let baseline = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_base_seed(SEED)
                .with_npos_consensus()
                .without_npos_genesis_bootstrap()
                .with_config_layer(|layer| {
                    layer
                        .write(
                            ["nexus", "staking", "stake_asset_id"],
                            fixture_stake_asset_id().to_string(),
                        )
                        .write(
                            ["nexus", "staking", "stake_escrow_account_id"],
                            fixture_escrow_id().to_string(),
                        )
                        .write(
                            ["nexus", "staking", "slash_sink_account_id"],
                            fixture_escrow_id().to_string(),
                        );
                }),
        );
        let baseline_genesis = baseline.genesis();
        assert_signed_nexus_amx_context_matches_preexecution(&baseline, &baseline_genesis);
        assert!(
            baseline_genesis
                .0
                .external_transactions()
                .filter_map(|transaction| match transaction.instructions() {
                    Executable::Instructions(instructions) => Some(instructions),
                    _ => None,
                })
                .flat_map(|instructions| instructions.iter())
                .all(|instruction| instruction
                    .as_any()
                    .downcast_ref::<RegisterPublicLaneValidator>()
                    .is_none()),
            "normal preview must not contain an active-validator bootstrap"
        );
        let baseline_context_hash = baseline
            .consensus_bootstrap_profile()
            .params
            .sumeragi_context
            .nexus_amx_context_hash;
        drop(baseline);
        let network = build_with_isolated_permit(
            NetworkBuilder::new()
                .with_peers(4)
                .with_base_seed(SEED)
                .with_npos_consensus()
                .without_npos_genesis_bootstrap()
                .with_config_layer(|layer| {
                    layer
                        .write(
                            ["nexus", "staking", "stake_asset_id"],
                            fixture_stake_asset_id().to_string(),
                        )
                        .write(
                            ["nexus", "staking", "stake_escrow_account_id"],
                            fixture_escrow_id().to_string(),
                        )
                        .write(
                            ["nexus", "staking", "slash_sink_account_id"],
                            fixture_escrow_id().to_string(),
                        );
                })
                .with_genesis_block(|topology, topology_entries| {
                    let peer_id = topology
                        .iter()
                        .next()
                        .expect("custom genesis topology must contain a peer")
                        .clone();

                    let stake_asset_id = fixture_stake_asset_id();
                    let escrow = fixture_escrow_id();
                    let stake_amount = SumeragiNposParameters::default().min_self_bond().clone();
                    let bootstrap = vec![
                        Register::account(Account::new(escrow.clone())).into(),
                        Register::asset_definition(
                            AssetDefinition::new(
                                stake_asset_id.clone(),
                                "XOR".to_owned(),
                                NumericSpec::fractional(9),
                                iroha_data_model::asset::AssetBalancePolicy::Global,
                                None,
                            )
                            .with_metadata(Metadata::default()),
                        )
                        .into(),
                        Mint::asset_quantity(
                            stake_amount.clone(),
                            AssetId::new(stake_asset_id.clone(), ALICE_ID.clone()),
                        )
                        .into(),
                    ];
                    let validator = vec![
                        RegisterPublicLaneValidator::new(
                            LaneId::SINGLE,
                            ALICE_ID.clone(),
                            peer_id,
                            ALICE_ID.clone(),
                            stake_amount.clone(),
                            Metadata::default(),
                            iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                                AssetId::new(stake_asset_id.clone(), ALICE_ID.clone()),
                                AssetId::new(stake_asset_id, escrow),
                                stake_amount,
                            ),
                        )
                        .into(),
                        ActivatePublicLaneValidator::new(LaneId::SINGLE, ALICE_ID.clone()).into(),
                    ];
                    unexecuted_genesis_factory_with_post_topology(
                        Vec::new(),
                        vec![bootstrap, validator],
                        topology,
                        topology_entries,
                    )
                }),
        );
        let genesis = network.genesis();
        assert_signed_nexus_amx_context_matches_preexecution(&network, &genesis);
        let metadata = consensus_handshake_metadata(&genesis)
            .expect("custom genesis must contain canonical consensus metadata");
        assert_eq!(
            metadata.sumeragi_context,
            network
                .consensus_bootstrap_profile()
                .params
                .sumeragi_context,
            "cached custom genesis must carry the final runtime profile"
        );
        assert_ne!(
            metadata.sumeragi_context.nexus_amx_context_hash, baseline_context_hash,
            "custom active-validator state must replace the normal preview projection"
        );
        assert!(
            genesis
                .0
                .external_transactions()
                .filter_map(|transaction| match transaction.instructions() {
                    Executable::Instructions(instructions) => Some(instructions),
                    _ => None,
                })
                .flat_map(|instructions| instructions.iter())
                .any(|instruction| instruction
                    .as_any()
                    .downcast_ref::<ActivatePublicLaneValidator>()
                    .is_some()),
            "custom genesis must retain its active-validator bootstrap"
        );
    }
    include!("lib/kura_restart_storage_test.rs");
    #[test]
    fn restart_genesis_file_reuses_latest_run_genesis_when_available() -> Result<()> {
        let root = tempdir()?;
        let env = Environment {
            dir: root.path().to_path_buf(),
        };
        let peer = NetworkPeer::builder().build(&env);
        assert_eq!(peer.restart_genesis_file(false), None);
        let genesis_path = peer.dir.join("run-1-genesis.nrt");
        fs::write(&genesis_path, b"genesis")?;
        assert_eq!(peer.restart_genesis_file(false), Some(genesis_path));
        assert_eq!(peer.restart_genesis_file(true), None);
        Ok(())
    }
    #[test]
    fn restart_genesis_file_skips_failed_early_run_when_later_genesis_exists() -> Result<()> {
        let root = tempdir()?;
        let env = Environment {
            dir: root.path().to_path_buf(),
        };
        let peer = NetworkPeer::builder().build(&env);
        let first_genesis_path = peer.dir.join("run-1-genesis.nrt");
        let later_genesis_path = peer.dir.join("run-3-genesis.nrt");
        fs::write(&first_genesis_path, b"stale genesis")?;
        fs::write(&later_genesis_path, b"latest genesis")?;
        assert_eq!(peer.restart_genesis_file(false), Some(later_genesis_path));
        Ok(())
    }
    fn parse_peer_run_config(path: &Path) -> Result<iroha_config::parameters::actual::Root> {
        let reader = ConfigReader::new()
            .with_env(MockEnv::default())
            .read_toml_with_extends(path)
            .map_err(|error| eyre!("read peer run config {}: {error:?}", path.display()))?;
        let user = reader
            .read_and_complete::<iroha_config::parameters::user::Root>()
            .map_err(|error| eyre!("complete peer run config {}: {error:?}", path.display()))?;
        user.parse()
            .map_err(|error| eyre!("parse peer run config {}: {error:?}", path.display()))
    }
    #[tokio::test(flavor = "current_thread")]
    async fn shared_genesis_preparation_precedes_all_peer_configs_and_keeps_async_progress()
    -> Result<()> {
        let network = NetworkBuilder::new().with_peers(4).build();
        let genesis = network.genesis();
        let expected = genesis.0.encode_wire()?;
        let async_thread = std::thread::current().id();
        let preparations = Arc::new(AtomicUsize::new(0));
        let timer_progress = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let preparation_count = Arc::clone(&preparations);
        let preparation = PreparedPeerGenesis::prepare_with_encoder(genesis, move |block| {
            // This assertion runs before waiting, so an accidental synchronous
            // implementation fails immediately instead of deadlocking the test.
            assert_ne!(std::thread::current().id(), async_thread);
            assert_eq!(preparation_count.fetch_add(1, Ordering::SeqCst), 0);
            started_tx.send(()).expect("announce encoder ownership");
            release_rx.recv().expect("async consumer releases encoder");
            NetworkPeer::canonical_genesis_bytes(block)
        });
        let progress = async {
            started_rx.await.expect("encoder reached blocking worker");
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
            timer_progress.store(true, Ordering::SeqCst);
            release_tx.send(()).expect("release blocking encoder");
        };
        let (prepared, ()) = tokio::join!(preparation, progress);
        let prepared = prepared?;
        assert!(timer_progress.load(Ordering::SeqCst));
        assert_eq!(preparations.load(Ordering::SeqCst), 1);
        assert_eq!(prepared.bytes.as_ref(), expected.as_slice());
        assert_eq!(prepared.network_id, network.network_id());
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let consumers = network.peers().iter().map(|peer| {
            let prepared = prepared.clone();
            let layers = &layers;
            let preparations = Arc::clone(&preparations);
            async move {
                assert_eq!(preparations.load(Ordering::SeqCst), 1);
                peer.write_run_config(layers.iter().map(Cow::Borrowed), Some(&prepared), None, 1)
                    .await?;
                let wire = tokio::fs::read(peer.dir.join("run-1-genesis.nrt")).await?;
                Ok::<_, Report>((prepared, wire))
            }
        });
        let consumers = futures::future::try_join_all(consumers).await?;
        assert_eq!(consumers.len(), 4);
        for (consumer, wire) in consumers {
            assert!(Arc::ptr_eq(&consumer.bytes, &prepared.bytes));
            assert_eq!(wire, expected);
        }
        assert_eq!(preparations.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn shared_genesis_preparation_error_never_publishes_bytes() -> Result<()> {
        let network = NetworkBuilder::new().with_peers(4).build();
        let prepared = PreparedPeerGenesis::prepare_with_encoder(network.genesis(), |_| {
            Err(eyre!("canonical genesis preparation fixture failure"))
        })
        .await;
        assert!(prepared.is_err());
        assert!(
            prepared
                .err()
                .expect("checked error")
                .to_string()
                .contains("canonical genesis preparation fixture failure")
        );
        assert!(PreparedPeerGenesis::prepare_optional(None).await?.is_none());
        assert!(network.peers().iter().all(|peer| !peer.is_running()));
        Ok(())
    }

    #[tokio::test]
    async fn peer_run_configs_reuse_exact_genesis_expected_hash_without_hashing_restart_artifact()
    -> Result<()> {
        let network = NetworkBuilder::new().with_peers(4).build();
        let peer = network.peers()[0].clone();
        let genesis = network.genesis();
        let expected_hash = genesis.0.hash();
        let layers = network
            .config_layers()
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        let no_local_genesis_config = peer
            .write_run_config(layers.iter().map(Cow::Borrowed), None, None, 0)
            .await?;
        assert_eq!(
            parse_peer_run_config(&no_local_genesis_config)?
                .genesis
                .expected_hash,
            expected_hash,
            "a first start without a local artifact must still receive the operator anchor"
        );
        let prepared_genesis = PreparedPeerGenesis::prepare(genesis).await?;
        let bootstrap_config = peer
            .write_run_config(
                layers.iter().map(Cow::Borrowed),
                Some(&prepared_genesis),
                None,
                1,
            )
            .await?;
        assert_eq!(
            parse_peer_run_config(&bootstrap_config)?
                .genesis
                .expected_hash,
            expected_hash
        );
        let genesis_path = peer
            .restart_genesis_file(false)
            .expect("bootstrap must persist a restart genesis artifact");
        // This test isolates config provenance. `irohad` separately tests that a
        // well-formed local genesis with a different hash is rejected.
        fs::write(&genesis_path, b"attacker-controlled replacement")?;
        let restart_config = peer
            .write_run_config(
                layers.iter().map(Cow::Borrowed),
                None,
                Some(&genesis_path),
                2,
            )
            .await?;
        assert_eq!(
            parse_peer_run_config(&restart_config)?
                .genesis
                .expected_hash,
            expected_hash,
            "restart must reuse the independently provisioned anchor"
        );
        let restart_table: Table = toml::from_str(&fs::read_to_string(&restart_config)?)?;
        let configured_file = get_nested_value(&restart_table, &["genesis", "file"])
            .and_then(Value::as_str)
            .expect("restart run config must select the persisted genesis artifact");
        let expected_file = genesis_path.to_string_lossy();
        assert_eq!(configured_file, expected_file.as_ref());
        assert_eq!(
            fs::read(&genesis_path)?,
            b"attacker-controlled replacement",
            "the harness must neither rewrite nor authenticate restart bytes from themselves"
        );
        Ok(())
    }
    #[test]
    fn consensus_first_boot_never_reasserts_a_key_after_history_loss() -> Result<()> {
        let root = tempdir()?;
        let records = root.path().join("custom-records");
        let log = root.path().join("custom-installation.log");
        assert!(!first_consensus_boot(0, &records, &log)?);
        assert!(first_consensus_boot(1, &records, &log)?);
        fs::create_dir(&records)?;
        assert!(!first_consensus_boot(1, &records, &log)?);
        fs::remove_dir(&records)?;
        fs::write(&log, b"retained installation")?;
        assert!(!first_consensus_boot(1, &records, &log)?);
        fs::remove_file(&log)?;
        assert!(!first_consensus_boot(2, &records, &log)?);
        assert!(!first_consensus_boot(3, &records, &log)?);
        Ok(())
    }
    #[test]
    fn kura_storage_dir_is_cleared_for_bootstrap_when_reset_for_bootstrap_is_true() -> Result<()> {
        let root = tempdir()?;
        let env = Environment {
            dir: root.path().to_path_buf(),
        };
        let peer = NetworkPeer::builder().build(&env);
        let storage_dir = peer.dir.join("storage");
        fs::create_dir_all(&storage_dir)?;
        fs::write(storage_dir.join("keep.marker"), b"remove")?;
        peer.prepare_kura_storage_dir(&storage_dir, true)?;
        assert!(
            !storage_dir.join("keep.marker").exists(),
            "bootstrap reset must clear stale files"
        );
        assert!(
            storage_dir.exists(),
            "storage directory must exist after preparation"
        );
        Ok(())
    }
}
