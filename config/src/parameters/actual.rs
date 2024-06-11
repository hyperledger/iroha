//! "Actual" layer of Iroha configuration parameters. It contains strongly-typed validated
//! structures in a way that is efficient for Iroha internally.

use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use error_stack::{Result, ResultExt};
use iroha_config_base::{read::ConfigReader, toml::TomlSource, WithOrigin};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    metadata::Limits as MetadataLimits, peer::PeerId, transaction::TransactionLimits, ChainId,
    LengthLimits,
};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use serde::{Deserialize, Serialize};
use url::Url;
pub use user::{DevTelemetry, Logger, Snapshot};

use crate::{
    kura::InitMode,
    parameters::{defaults, user},
};

/// Parsed configuration root
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct Root {
    pub common: Common,
    pub network: Network,
    pub genesis: Genesis,
    pub torii: Torii,
    pub kura: Kura,
    pub sumeragi: Sumeragi,
    pub block_sync: BlockSync,
    pub transaction_gossiper: TransactionGossiper,
    pub live_query_store: LiveQueryStore,
    pub logger: Logger,
    pub queue: Queue,
    pub snapshot: Snapshot,
    pub telemetry: Option<Telemetry>,
    pub dev_telemetry: DevTelemetry,
    pub chain_wide: ChainWide,
}

/// See [`Root::from_toml_source`]
#[derive(thiserror::Error, Debug, Copy, Clone)]
#[error("Failed to read configuration from a given TOML source")]
pub struct FromTomlSourceError;

impl Root {
    /// A shorthand to read config from a single provided TOML.
    /// For testing purposes.
    /// # Errors
    /// If config reading/parsing fails.
    pub fn from_toml_source(src: TomlSource) -> Result<Self, FromTomlSourceError> {
        ConfigReader::new()
            .with_toml_source(src)
            .read_and_complete::<user::Root>()
            .change_context(FromTomlSourceError)?
            .parse()
            .change_context(FromTomlSourceError)
    }
}

/// Common options shared between multiple places
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Common {
    pub chain_id: ChainId,
    pub key_pair: KeyPair,
    pub peer_id: PeerId,
}

impl Common {
    /// Construct an id of this peer
    pub fn peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }
}

/// Network options
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Network {
    pub address: WithOrigin<SocketAddr>,
    pub idle_timeout: Duration,
}

/// Parsed genesis configuration
#[derive(Debug, Clone)]
pub struct Genesis {
    /// Genesis account public key
    pub public_key: PublicKey,
    /// Path to `GenesisTransaction`.
    /// If it is none, the peer can only observe the genesis block.
    /// If it is some, the peer is responsible for submitting the genesis block.
    pub signed_file: Option<WithOrigin<PathBuf>>,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy)]
pub struct Queue {
    pub capacity: NonZeroUsize,
    pub capacity_per_user: NonZeroUsize,
    pub transaction_time_to_live: Duration,
    pub future_threshold: Duration,
}

#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Kura {
    pub init_mode: InitMode,
    pub store_dir: WithOrigin<PathBuf>,
    pub debug_output_new_blocks: bool,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            transaction_time_to_live: defaults::queue::TRANSACTION_TIME_TO_LIVE,
            future_threshold: defaults::queue::FUTURE_THRESHOLD,
            capacity: defaults::queue::CAPACITY,
            capacity_per_user: defaults::queue::CAPACITY_PER_USER,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct Sumeragi {
    pub trusted_peers: WithOrigin<TrustedPeers>,
    pub debug_force_soft_fork: bool,
}

#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct TrustedPeers {
    pub myself: PeerId,
    pub others: UniqueVec<PeerId>,
}

impl TrustedPeers {
    /// Returns a list of trusted peers which is guaranteed to have at
    /// least one element - the id of the peer itself.
    pub fn into_non_empty_vec(self) -> UniqueVec<PeerId> {
        std::iter::once(self.myself).chain(self.others).collect()
    }
}

impl Sumeragi {
    /// Tells whether a trusted peers list has some other peers except for the peer itself
    pub fn contains_other_trusted_peers(&self) -> bool {
        self.trusted_peers.value().others.len() > 1
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)]
pub struct LiveQueryStore {
    pub idle_time: Duration,
}

impl Default for LiveQueryStore {
    fn default() -> Self {
        Self {
            idle_time: defaults::torii::QUERY_IDLE_TIME,
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy)]
pub struct BlockSync {
    pub gossip_period: Duration,
    pub gossip_max_size: NonZeroU32,
}

#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)]
pub struct TransactionGossiper {
    pub gossip_period: Duration,
    pub gossip_max_size: NonZeroU32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ChainWide {
    pub max_transactions_in_block: NonZeroU32,
    pub block_time: Duration,
    pub commit_time: Duration,
    pub transaction_limits: TransactionLimits,
    pub domain_metadata_limits: MetadataLimits,
    pub asset_definition_metadata_limits: MetadataLimits,
    pub account_metadata_limits: MetadataLimits,
    pub asset_metadata_limits: MetadataLimits,
    pub trigger_metadata_limits: MetadataLimits,
    pub ident_length_limits: LengthLimits,
    pub executor_runtime: WasmRuntime,
    pub wasm_runtime: WasmRuntime,
}

impl ChainWide {
    /// Calculate pipeline time based on the block time and commit time
    pub fn pipeline_time(&self) -> Duration {
        self.block_time + self.commit_time
    }

    /// Estimates as `block_time + commit_time / 2`
    pub fn consensus_estimation(&self) -> Duration {
        self.block_time + (self.commit_time / 2)
    }
}

impl Default for ChainWide {
    fn default() -> Self {
        Self {
            max_transactions_in_block: defaults::chain_wide::MAX_TXS,
            block_time: defaults::chain_wide::BLOCK_TIME,
            commit_time: defaults::chain_wide::COMMIT_TIME,
            transaction_limits: defaults::chain_wide::TRANSACTION_LIMITS,
            domain_metadata_limits: defaults::chain_wide::METADATA_LIMITS,
            account_metadata_limits: defaults::chain_wide::METADATA_LIMITS,
            asset_definition_metadata_limits: defaults::chain_wide::METADATA_LIMITS,
            asset_metadata_limits: defaults::chain_wide::METADATA_LIMITS,
            trigger_metadata_limits: defaults::chain_wide::METADATA_LIMITS,
            ident_length_limits: defaults::chain_wide::IDENT_LENGTH_LIMITS,
            executor_runtime: WasmRuntime::default(),
            wasm_runtime: WasmRuntime::default(),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WasmRuntime {
    pub fuel_limit: u64,
    // TODO: wrap into a `Bytes` newtype
    pub max_memory_bytes: u32,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self {
            fuel_limit: defaults::chain_wide::WASM_FUEL_LIMIT,
            max_memory_bytes: defaults::chain_wide::WASM_MAX_MEMORY_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct Torii {
    pub address: WithOrigin<SocketAddr>,
    pub max_content_len_bytes: u64,
}

/// Complete configuration needed to start regular telemetry.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct Telemetry {
    pub name: String,
    pub url: Url,
    pub min_retry_period: Duration,
    pub max_retry_delay_exponent: u8,
}
