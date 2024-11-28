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

use getset::Getters;
use derive_builder::Builder;
// use derive_more::Display;

// #[derive(Debug, Display, serde::Deserialize, PartialEq, Eq, Copy, Clone)]
// #[display(fmt = "Config could not be constructed. {_0}")]
// #[allow(missing_docs)]
// pub struct RootBuildError(&'static str);

// impl From<derive_builder::UninitializedFieldError> for RootBuildError {
//     fn from(ufe: derive_builder::UninitializedFieldError) -> RootBuildError { ufe.into() }
// }
// impl error_stack::Context for RootBuildError {}

/// Parsed configuration root
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
// #[builder(build_fn(error = "RootBuildError"))]
#[allow(missing_docs)]
pub struct Root {
    ///
    common: Common,
    ///
    network: Network,
    ///
    genesis: Genesis,
    ///
    torii: Torii,
    ///
    kura: Kura,
    ///
    sumeragi: Sumeragi,
    ///
    block_sync: BlockSync,
    ///
    transaction_gossiper: TransactionGossiper,
    ///
    live_query_store: LiveQueryStore,
    ///
    logger: Logger,
    ///
    queue: Queue,
    ///
    snapshot: Snapshot,
    ///
    telemetry: Option<Telemetry>,
    ///
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
    ///
    chain: ChainId,
    ///
    key_pair: KeyPair,
    ///
    peer: Peer,
    ///
    trusted_peers: WithOrigin<TrustedPeers>,
}

/// Network options
#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Network {
    ///
    address: WithOrigin<SocketAddr>,
    ///
    public_address: WithOrigin<SocketAddr>,
    ///
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
    ///
    #[builder(default = "defaults::queue::CAPACITY")]
    capacity: NonZeroUsize,
    ///
    #[builder(default = "defaults::queue::CAPACITY_PER_USER")]
    capacity_per_user: NonZeroUsize,
    ///
    #[builder(default = "defaults::queue::TRANSACTION_TIME_TO_LIVE")]
    transaction_time_to_live: Duration,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Kura {
    ///
    init_mode: InitMode,
    ///
    store_dir: WithOrigin<PathBuf>,
    ///
    blocks_in_memory: NonZeroUsize,
    ///
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
    ///
    debug_force_soft_fork: bool,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct TrustedPeers {
    ///
    myself: Peer,
    ///
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
    ///
    #[builder(default = "defaults::torii::QUERY_IDLE_TIME")]
    idle_time: Duration,
    ///
    #[builder(default = "defaults::torii::QUERY_STORE_CAPACITY")]
    capacity: NonZeroUsize,
    ///
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
    ///
    gossip_period: Duration,
    ///
    gossip_size: NonZeroU32,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct TransactionGossiper {
    ///
    gossip_period: Duration,
    ///
    gossip_size: NonZeroU32,
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Torii {
    ///
    address: WithOrigin<SocketAddr>,
    ///
    max_content_len: Bytes<u64>,
}

/// Complete configuration needed to start regular telemetry.
#[allow(missing_docs)]
#[derive(Debug, Clone, Getters, Builder)]
#[getset(get = "pub")]
#[builder(pattern = "owned")]
pub struct Telemetry {
    ///
    name: String,
    ///
    url: Url,
    ///
    min_retry_period: Duration,
    ///
    max_retry_delay_exponent: u8,
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
