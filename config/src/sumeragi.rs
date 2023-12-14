//! `Sumeragi` configuration. Contains both block commit and Gossip-related configuration.
use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

use eyre::{Result, WrapErr};
use iroha_config_base::derive::{view, Documented, Proxy};
use iroha_crypto::prelude::*;
use iroha_data_model::prelude::*;
use iroha_primitives::{unique_vec, unique_vec::UniqueVec};
use serde::{Deserialize, Serialize};

use self::default::*;

/// Module with a set of default values.
pub mod default {
    /// Default number of miliseconds the peer waits for transactions before creating a block.
    pub const DEFAULT_BLOCK_TIME_MS: u64 = 2000;
    /// Default amount of time allocated for voting on a block before a peer can ask for a view change.
    pub const DEFAULT_COMMIT_TIME_LIMIT_MS: u64 = 4000;
    /// Unused const. Should be removed in the future.
    pub const DEFAULT_ACTOR_CHANNEL_CAPACITY: u32 = 100;
    /// Default duration in ms between every transaction gossip.
    pub const DEFAULT_GOSSIP_PERIOD_MS: u64 = 1000;
    /// Default maximum number of transactions sent in single gossip message.
    pub const DEFAULT_GOSSIP_BATCH_SIZE: u32 = 500;
    /// Default maximum number of transactions in block.
    pub const DEFAULT_MAX_TRANSACTIONS_IN_BLOCK: u32 = 2_u32.pow(9);

    /// Default estimation of consensus duration.
    #[allow(clippy::integer_division)]
    pub const DEFAULT_CONSENSUS_ESTIMATION_MS: u64 =
        DEFAULT_BLOCK_TIME_MS + (DEFAULT_COMMIT_TIME_LIMIT_MS / 2);
}

// Generate `ConfigurationView` without keys
view! {
    /// `Sumeragi` configuration.
    /// [`struct@Configuration`] provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and a list of `TRUSTED_PEERS`.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Proxy, Documented)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "SUMERAGI_")]
    pub struct Configuration {
        /// The key pair consisting of a private and a public key.
        //TODO: consider putting a `#[serde(skip)]` on the proxy struct here
        #[view(ignore)]
        pub key_pair: KeyPair,
        /// Current Peer Identification.
        pub peer_id: PeerId,
        /// The period of time a peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
        pub block_time_ms: u64,
        /// Optional list of predefined trusted peers.
        pub trusted_peers: TrustedPeers,
        /// The period of time a peer waits for `CommitMessage` from the proxy tail.
        pub commit_time_limit_ms: u64,
        /// The upper limit of the number of transactions per block.
        pub max_transactions_in_block: u32,
        /// Buffer capacity of actor's MPSC channel
        pub actor_channel_capacity: u32,
        /// max number of transactions in tx gossip batch message. While configuring this, pay attention to `p2p` max message size.
        pub gossip_batch_size: u32,
        /// Period in milliseconds for pending transaction gossiping between peers.
        pub gossip_period_ms: u64,
        #[cfg(debug_assertions)]
        /// Only used in testing. Causes the genesis peer to withhold blocks when it
        /// is the proxy tail.
        pub debug_force_soft_fork: bool,
    }
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            key_pair: None,
            peer_id: None,
            trusted_peers: None,
            block_time_ms: Some(DEFAULT_BLOCK_TIME_MS),
            commit_time_limit_ms: Some(DEFAULT_COMMIT_TIME_LIMIT_MS),
            actor_channel_capacity: Some(DEFAULT_ACTOR_CHANNEL_CAPACITY),
            gossip_batch_size: Some(DEFAULT_GOSSIP_BATCH_SIZE),
            gossip_period_ms: Some(DEFAULT_GOSSIP_PERIOD_MS),
            max_transactions_in_block: Some(DEFAULT_MAX_TRANSACTIONS_IN_BLOCK),
            #[cfg(debug_assertions)]
            debug_force_soft_fork: Some(false),
        }
    }
}
impl ConfigurationProxy {
    /// To be used for proxy finalisation. Should only be
    /// used if no peers are present.
    ///
    /// # Panics
    /// The [`peer_id`] field of [`Self`]
    /// has not been initialized prior to calling this method.
    pub fn insert_self_as_trusted_peers(&mut self) {
        let peer_id = self
            .peer_id
            .as_ref()
            .expect("Insertion of `self` as `trusted_peers` implies that `peer_id` field should be initialized");
        self.trusted_peers = if let Some(mut trusted_peers) = self.trusted_peers.take() {
            trusted_peers.peers.push(peer_id.clone());
            Some(trusted_peers)
        } else {
            Some(TrustedPeers {
                peers: unique_vec![peer_id.clone()],
            })
        };
    }
}

impl Configuration {
    /// Time estimation from receiving a transaction to storing it in
    /// a block on all peers for the "sunny day" scenario.
    #[inline]
    #[must_use]
    pub const fn pipeline_time_ms(&self) -> u64 {
        self.block_time_ms + self.commit_time_limit_ms
    }
}

/// Part of the [`Configuration`]. It is separated from the main structure in order to be able
/// to load it from a separate file (see [`TrustedPeers::from_path`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(transparent)]
#[repr(transparent)]
pub struct TrustedPeers {
    /// Optional list of predefined trusted peers. Must contain unique
    /// entries. Custom deserializer raises error if duplicates found.
    #[serde(deserialize_with = "UniqueVec::display_deserialize_failing_on_duplicates")]
    pub peers: UniqueVec<PeerId>,
}

impl TrustedPeers {
    /// Load trusted peers variables from JSON.
    ///
    /// # Errors
    /// - File not found
    /// - File is not Valid JSON.
    /// - File is valid JSON, but configuration options don't match.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Self> {
        let file = File::open(&path)
            .wrap_err_with(|| format!("Failed to open trusted peers file {:?}", &path))?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader)
            .wrap_err("Failed to deserialize json from reader")
            .map_err(Into::into)
    }
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        #[allow(unused_variables)]
        pub fn arb_proxy()
            (key_pair in Just(None),
             peer_id in Just(None),
             block_time_ms in prop::option::of(Just(DEFAULT_BLOCK_TIME_MS)),
             trusted_peers in Just(None),
             commit_time_limit_ms in prop::option::of(Just(DEFAULT_COMMIT_TIME_LIMIT_MS)),
             actor_channel_capacity in prop::option::of(Just(DEFAULT_ACTOR_CHANNEL_CAPACITY)),
             gossip_batch_size in prop::option::of(Just(DEFAULT_GOSSIP_BATCH_SIZE)),
             gossip_period_ms in prop::option::of(Just(DEFAULT_GOSSIP_PERIOD_MS)),
            max_transactions_in_block in prop::option::of(Just(DEFAULT_MAX_TRANSACTIONS_IN_BLOCK)),
             debug_force_soft_fork in prop::option::of(Just(false)),
            )
            -> ConfigurationProxy {
            ConfigurationProxy {
                key_pair,
                peer_id,
                block_time_ms,
                trusted_peers,
                commit_time_limit_ms,
                max_transactions_in_block,
                actor_channel_capacity,
                gossip_batch_size,
                gossip_period_ms,
                #[cfg(debug_assertions)]
                debug_force_soft_fork
            }
        }
    }
}
