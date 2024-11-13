//! "Actual" layer of Iroha configuration parameters. It contains strongly-typed validated
//! structures in a way that is efficient for Iroha internally.

use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use error_stack::{Result, ResultExt};
use iroha_config_base::{read::ConfigReader, toml::TomlSource, util::Bytes, WithOrigin};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{
    peer::{Peer, PeerId},
    ChainId, Identifiable,
};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
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
    pub chain: ChainId,
    pub key_pair: KeyPair,
    pub peer: Peer,
    pub trusted_peers: WithOrigin<TrustedPeers>,
}

/// Network options
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Network {
    pub address: WithOrigin<SocketAddr>,
    pub public_address: WithOrigin<SocketAddr>,
    pub idle_timeout: Duration,
}

/// Parsed genesis configuration
#[derive(Debug, Clone)]
pub struct Genesis {
    /// Genesis account public key
    pub public_key: PublicKey,
    /// Path to `GenesisBlock`.
    /// If it is none, the peer can only observe the genesis block.
    /// If it is some, the peer is responsible for submitting the genesis block.
    pub file: Option<WithOrigin<PathBuf>>,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy)]
pub struct Queue {
    pub capacity: NonZeroUsize,
    pub capacity_per_user: NonZeroUsize,
    pub transaction_time_to_live: Duration,
}

#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct Kura {
    pub init_mode: InitMode,
    pub store_dir: WithOrigin<PathBuf>,
    pub blocks_in_memory: NonZeroUsize,
    pub debug_output_new_blocks: bool,
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

#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
pub struct Sumeragi {
    pub debug_force_soft_fork: bool,
}

#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct TrustedPeers {
    pub myself: Peer,
    pub others: UniqueVec<Peer>,
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

#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)]
pub struct LiveQueryStore {
    pub idle_time: Duration,
    pub capacity: NonZeroUsize,
    pub capacity_per_user: NonZeroUsize,
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
#[derive(Debug, Clone, Copy)]
pub struct BlockSync {
    pub gossip_period: Duration,
    pub gossip_size: NonZeroU32,
}

#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)]
pub struct TransactionGossiper {
    pub gossip_period: Duration,
    pub gossip_size: NonZeroU32,
}

#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct Torii {
    pub address: WithOrigin<SocketAddr>,
    pub max_content_len: Bytes<u64>,
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
