//! "Actual" layer of Iroha configuration parameters. It contains strongly-typed validated
//! structures in a way that is efficient for Iroha internally.

use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use derive_builder::Builder;
use error_stack::{Result, ResultExt};
use getset::{Getters, MutGetters, Setters};
use iroha_config_base::{read::ConfigReader, toml::TomlSource, util::Bytes, WithOrigin};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    peer::{Peer, PeerId},
    ChainId, Identifiable,
};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use url::Url;

use crate::{
    client_api::ConfigDTO,
    kura::InitMode,
    logger::{Directives, Format as LoggerFormat},
    parameters::{defaults, user},
    snapshot::Mode as SnapshotMode,
};

/// Parsed configuration root
#[derive(Debug, Clone, Getters, MutGetters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
#[allow(missing_docs)]
pub struct Root {
    /// Common options
    common: Common,
    /// Network options
    network: Network,
    /// Genesis options
    genesis: Genesis,
    /// Torii options
    torii: Torii,
    /// Kura options
    kura: Kura,
    /// Sumeragi options
    sumeragi: Sumeragi,
    /// Block sync options
    block_sync: BlockSync,
    /// Transaction gossiper options
    transaction_gossiper: TransactionGossiper,
    /// Live query store options
    live_query_store: LiveQueryStore,
    /// Logger options
    #[getset(get_mut = "pub")]
    logger: Logger,
    /// Queue options
    queue: Queue,
    /// Snapshot options
    snapshot: Snapshot,
    /// Telemetry options
    telemetry: Option<Telemetry>,
    /// Dev telemetry options
    dev_telemetry: DevTelemetry,
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
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Common {
    /// Id of blockchain
    chain: ChainId,
    /// Pair of public/private keys
    key_pair: KeyPair,
    /// Peer options
    peer: Peer,
    /// Trusted peers options
    trusted_peers: WithOrigin<TrustedPeers>,
}

/// Network options
#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Network {
    /// Address
    address: WithOrigin<SocketAddr>,
    /// Public address
    public_address: WithOrigin<SocketAddr>,
    /// Idle timeout
    idle_timeout: Duration,
}

/// Parsed genesis configuration
#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Genesis {
    /// Genesis account public key
    public_key: PublicKey,
    /// Path to `GenesisBlock`.
    /// If it is none, the peer can only observe the genesis block.
    /// If it is some, the peer is responsible for submitting the genesis block.
    file: Option<WithOrigin<PathBuf>>,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Queue {
    /// Queue capacity
    #[builder(default = "defaults::queue::CAPACITY")]
    capacity: NonZeroUsize,
    /// Capacity per user
    #[builder(default = "defaults::queue::CAPACITY_PER_USER")]
    capacity_per_user: NonZeroUsize,
    /// Transaction TTL
    #[builder(default = "defaults::queue::TRANSACTION_TIME_TO_LIVE")]
    transaction_time_to_live: Duration,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Kura {
    /// Initialization mode
    init_mode: InitMode,
    /// Path to storage directory
    store_dir: WithOrigin<PathBuf>,
    /// Number of blocks in memory
    #[builder(default = "defaults::kura::BLOCKS_IN_MEMORY")]
    blocks_in_memory: NonZeroUsize,
    /// Include new blocks in debug output
    debug_output_new_blocks: bool,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            transaction_time_to_live: defaults::queue::TRANSACTION_TIME_TO_LIVE,
            capacity: defaults::queue::CAPACITY,
            capacity_per_user: defaults::queue::CAPACITY_PER_USER,
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Sumeragi {
    /// Genesis peer withhold blocks as proxy tail
    debug_force_soft_fork: bool,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct TrustedPeers {
    /// The local peer's information
    myself: Peer,
    /// Other trusted peers
    others: UniqueVec<Peer>,
}

impl TrustedPeers {
    /// Returns a list of trusted peers which is guaranteed to have at
    /// least one element - the id of the peer itself.
    pub fn into_non_empty_vec(self) -> UniqueVec<PeerId> {
        std::iter::once(self.myself)
            .chain(self.others)
            .map(|peer| peer.id().clone())
            .collect()
    }

    /// Tells whether a trusted peers list has some other peers except for the peer itself
    pub fn contains_other_trusted_peers(&self) -> bool {
        !self.others.is_empty()
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct LiveQueryStore {
    /// Idle time
    #[builder(default = "defaults::torii::QUERY_IDLE_TIME")]
    idle_time: Duration,
    /// Query capacity
    #[builder(default = "defaults::torii::QUERY_STORE_CAPACITY")]
    capacity: NonZeroUsize,
    /// Query capacity per user
    #[builder(default = "defaults::torii::QUERY_STORE_CAPACITY_PER_USER")]
    capacity_per_user: NonZeroUsize,
}

impl Default for LiveQueryStore {
    fn default() -> Self {
        Self {
            idle_time: defaults::torii::QUERY_IDLE_TIME,
            capacity: defaults::torii::QUERY_STORE_CAPACITY,
            capacity_per_user: defaults::torii::QUERY_STORE_CAPACITY_PER_USER,
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct BlockSync {
    /// Gossip period
    #[builder(default = "defaults::network::BLOCK_GOSSIP_PERIOD")]
    gossip_period: Duration,
    /// Gossip size
    #[builder(default = "defaults::network::BLOCK_GOSSIP_SIZE")]
    gossip_size: NonZeroU32,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct TransactionGossiper {
    /// Gossip period
    #[builder(default = "defaults::network::TRANSACTION_GOSSIP_PERIOD")]
    gossip_period: Duration,
    /// Gossip size
    #[builder(default = "defaults::network::TRANSACTION_GOSSIP_SIZE")]
    gossip_size: NonZeroU32,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Torii {
    /// Torii address
    address: WithOrigin<SocketAddr>,
    /// Maximum content length
    #[builder(default = "defaults::torii::MAX_CONTENT_LEN")]
    max_content_len: Bytes<u64>,
}

/// Complete configuration needed to start regular telemetry.
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Telemetry {
    /// Name
    name: String,
    /// Url
    url: Url,
    /// Minimal retry period
    #[builder(default = "defaults::telemetry::MIN_RETRY_PERIOD")]
    min_retry_period: Duration,
    /// Maximum exponent for the retry delay
    #[builder(default = "defaults::telemetry::MAX_RETRY_DELAY_EXPONENT")]
    max_retry_delay_exponent: u8,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Default, Getters, Setters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Logger {
    /// Level
    #[getset(get = "pub", set = "pub")]
    level: Directives,
    /// Format
    format: LoggerFormat,
}

impl From<&'_ Logger> for ConfigDTO {
    fn from(value: &'_ Logger) -> Self {
        Self {
            logger: value.into(),
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Snapshot {
    /// Mode
    mode: SnapshotMode,
    /// Create intervals
    #[builder(default = "defaults::snapshot::CREATE_EVERY")]
    create_every: Duration,
    /// Storage directory
    store_dir: WithOrigin<PathBuf>,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct DevTelemetry {
    /// Output file
    out_file: Option<WithOrigin<PathBuf>>,
}

#[cfg(test)]
mod tests {
    use iroha_primitives::{addr::socket_addr, unique_vec};

    use super::*;

    fn dummy_peer(port: u16) -> Peer {
        Peer::new(
            socket_addr!(127.0.0.1:port),
            KeyPair::random().into_parts().0,
        )
    }

    #[test]
    fn no_trusted_peers() {
        let value = TrustedPeers {
            myself: dummy_peer(80),
            others: unique_vec![],
        };
        assert!(!value.contains_other_trusted_peers());
    }

    #[test]
    fn one_trusted_peer() {
        let value = TrustedPeers {
            myself: dummy_peer(80),
            others: unique_vec![dummy_peer(81)],
        };
        assert!(value.contains_other_trusted_peers());
    }

    #[test]
    fn many_trusted_peers() {
        let value = TrustedPeers {
            myself: dummy_peer(80),
            others: unique_vec![dummy_peer(1), dummy_peer(2), dummy_peer(3), dummy_peer(4),],
        };
        assert!(value.contains_other_trusted_peers());
    }
}
