use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use iroha_config_base::ByteSize;
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    metadata::Limits as MetadataLimits, peer::PeerId, transaction::TransactionLimits, ChainId,
    LengthLimits, Level,
};
use iroha_genesis::RawGenesisBlock;
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    kura::Mode,
    logger::Format,
    parameters::{defaults, user_layer},
};

#[derive(Debug, Clone)]
pub struct Root {
    pub iroha: Iroha,
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
    pub regular_telemetry: Option<RegularTelemetry>,
    pub dev_telemetry: Option<DevTelemetry>,
    pub chain_wide: ChainWide,
}

#[derive(Debug, Clone)]
pub struct Iroha {
    pub chain_id: ChainId,
    pub key_pair: KeyPair,
    pub p2p_address: SocketAddr,
}

impl Iroha {
    pub fn peer_id(&self) -> PeerId {
        PeerId::new(self.p2p_address.clone(), self.key_pair.public_key().clone())
    }
}

#[derive(Debug, Clone)]
pub enum Genesis {
    /// The peer can only observe the genesis block
    Partial {
        /// Genesis account public key
        public_key: PublicKey,
    },
    /// The peer is responsible for submitting the genesis block
    Full {
        /// Genesis account key pair
        key_pair: KeyPair,
        /// Path to the [`RawGenesisBlock`]
        file: PathBuf,
    },
}

impl Genesis {
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::Partial { public_key } => public_key,
            Self::Full { key_pair, .. } => key_pair.public_key(),
        }
    }

    pub fn key_pair(&self) -> Option<&KeyPair> {
        match self {
            Self::Partial { .. } => None,
            Self::Full { key_pair, .. } => Some(key_pair),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Kura {
    pub init_mode: Mode,
    pub block_store_path: PathBuf,
    pub debug_output_new_blocks: bool,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            transaction_time_to_live: defaults::queue::DEFAULT_TRANSACTION_TIME_TO_LIVE,
            future_threshold: defaults::queue::DEFAULT_FUTURE_THRESHOLD,
            size: defaults::queue::DEFAULT_MAX_TRANSACTIONS_IN_QUEUE,
            size_per_user: defaults::queue::DEFAULT_MAX_TRANSACTIONS_IN_QUEUE_PER_USER,
        }
    }
}

pub use user_layer::{Logger, Queue, Snapshot};

#[derive(Debug, Clone)]
pub struct Sumeragi {
    pub trusted_peers: UniqueVec<PeerId>,
    pub debug_force_soft_fork: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct LiveQueryStore {
    pub query_idle_time: Duration,
}

impl Default for LiveQueryStore {
    fn default() -> Self {
        Self {
            query_idle_time: defaults::torii::DEFAULT_QUERY_IDLE_TIME,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BlockSync {
    pub gossip_period: Duration,
    pub batch_size: NonZeroU32,
}

#[derive(Debug, Clone, Copy)]
pub struct TransactionGossiper {
    pub gossip_period: Duration,
    pub batch_size: NonZeroU32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ChainWide {
    pub max_transactions_in_block: NonZeroU32,
    pub block_time: Duration,
    pub commit_time: Duration,
    pub transaction_limits: TransactionLimits,
    pub asset_metadata_limits: MetadataLimits,
    pub asset_definition_metadata_limits: MetadataLimits,
    pub account_metadata_limits: MetadataLimits,
    pub domain_metadata_limits: MetadataLimits,
    pub identifier_length_limits: LengthLimits,
    pub wasm_runtime: WasmRuntime,
}

impl ChainWide {
    pub fn pipeline_time(&self) -> Duration {
        self.block_time + self.commit_time
    }
}

impl Default for ChainWide {
    fn default() -> Self {
        Self {
            max_transactions_in_block: defaults::chain_wide::DEFAULT_MAX_TXS,
            block_time: defaults::chain_wide::DEFAULT_BLOCK_TIME,
            commit_time: defaults::chain_wide::DEFAULT_COMMIT_TIME,
            transaction_limits: defaults::chain_wide::DEFAULT_TRANSACTION_LIMITS,
            domain_metadata_limits: defaults::chain_wide::DEFAULT_METADATA_LIMITS,
            account_metadata_limits: defaults::chain_wide::DEFAULT_METADATA_LIMITS,
            asset_definition_metadata_limits: defaults::chain_wide::DEFAULT_METADATA_LIMITS,
            asset_metadata_limits: defaults::chain_wide::DEFAULT_METADATA_LIMITS,
            identifier_length_limits: defaults::chain_wide::DEFAULT_IDENT_LENGTH_LIMITS,
            wasm_runtime: WasmRuntime::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WasmRuntime {
    pub fuel_limit: u64,
    pub max_memory: ByteSize<u32>,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self {
            fuel_limit: defaults::chain_wide::DEFAULT_WASM_FUEL_LIMIT,
            max_memory: ByteSize(defaults::chain_wide::DEFAULT_WASM_MAX_MEMORY),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Torii {
    pub address: SocketAddr,
    pub max_content_len: ByteSize<u64>,
}

/// Complete configuration needed to start regular telemetry.
#[derive(Debug, Clone)]
pub struct RegularTelemetry {
    #[allow(missing_docs)]
    pub name: String,
    #[allow(missing_docs)]
    pub url: Url,
    #[allow(missing_docs)]
    pub min_retry_period: Duration,
    #[allow(missing_docs)]
    pub max_retry_delay_exponent: u8,
}

/// Complete configuration needed to start dev telemetry.
#[derive(Debug, Clone)]
pub struct DevTelemetry {
    #[allow(missing_docs)]
    pub file: PathBuf,
}
