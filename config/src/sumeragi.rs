//! `Sumeragi` configuration. Contains both block commit and Gossip-related configuration.
#![allow(clippy::std_instead_of_core, clippy::arithmetic_side_effects)]
use std::{collections::HashSet, fmt::Debug};

use eyre::Result;
use iroha_config_base::{view, Configuration, Documented};
use iroha_crypto::prelude::*;
use iroha_data_model::prelude::*;
use serde::{Deserialize, Serialize};

// Generate `ConfigurationView` without keys
view! {
    /// `Sumeragi` configuration.
    /// [`struct@Configuration`] provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and a list of `TRUSTED_PEERS`.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
    #[serde(try_from = "ConfigurationBuilder")]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "SUMERAGI_")]
    pub struct Configuration {
        /// The key pair consisting of a private and a public key.
        //TODO: consider putting a `#[serde(skip)]` on the proxy struct here
        #[view(ignore)]
        key_pair: KeyPair,
        /// Current Peer Identification.
        peer_id: PeerId,
        /// The period of time a peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
        #[config(default = "2000")]
        block_time_ms: u64,
        /// List of predefined ordered trusted peers. Must contain unique entries
        #[config(default = "OrderedSet(Vec::new())")]
        trusted_peers: OrderedSet<PeerId>,
        /// The period of time a peer waits for `CommitMessage` from the proxy tail.
        #[config(default = "4000")]
        commit_time_limit_ms: u64,
        /// The upper limit of the number of transactions per block.
        #[config(default = "2_u32.pow(9)")]
        max_transactions_in_block: u32,
        /// Buffer capacity of actor's MPSC channel
        #[config(default = "100")]
        #[deprecated]
        actor_channel_capacity: u32,
        /// max number of transactions in tx gossip batch message. While configuring this, pay attention to `p2p` max message size.
        #[config(default = "500")]
        gossip_batch_size: u32,
        /// Period in milliseconds for pending transaction gossiping between peers.
        #[config(default = "1000")]
        gossip_period_ms: u64,
        #[cfg(debug_assertions)]
        /// Only used in testing. Causes the genesis peer to withhold blocks when it
        /// is the proxy tail.
        #[config(default = "false")]
        debug_force_soft_fork: bool,
    }
}

/// A set that preserves insertion order
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrderedSet<T>(Vec<T>);

impl<T> Default for OrderedSet<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> OrderedSet<T> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Configuration {
    /// Default estimation of consensus duration.
    #[allow(clippy::integer_division, non_snake_case)]
    pub fn DEFAULT_CONSENSUS_ESTIMATION_MS() -> u64 {
        Self::DEFAULT_BLOCK_TIME_MS() + (Self::DEFAULT_COMMIT_TIME_LIMIT_MS() / 2)
    }
}

impl<'de, T: core::fmt::Display + Eq + core::hash::Hash + Deserialize<'de>> Deserialize<'de>
    for OrderedSet<T>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let peers = Vec::deserialize(deserializer)?;

        peers.iter().try_fold(HashSet::new(), |mut acc, peer| {
            if acc.insert(peer) {
                Ok::<_, serde::de::value::Error>(acc)
            } else {
                Err(serde::de::Error::custom(format!(
                    "{}: Duplicate element found",
                    &peer
                )))
            }
        });

        // NOTE: Return peers in the order as defined in configuration
        Ok(OrderedSet(peers))
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
             block_time_ms in prop::option::of(Just(Configuration::DEFAULT_BLOCK_TIME_MS())),
             trusted_peers in prop::option::of(Just(Configuration::DEFAULT_TRUSTED_PEERS())),
             commit_time_limit_ms in prop::option::of(Just(Configuration::DEFAULT_COMMIT_TIME_LIMIT_MS())),
             actor_channel_capacity in prop::option::of(Just(Configuration::DEFAULT_ACTOR_CHANNEL_CAPACITY())),
             gossip_batch_size in prop::option::of(Just(Configuration::DEFAULT_GOSSIP_BATCH_SIZE())),
             gossip_period_ms in prop::option::of(Just(Configuration::DEFAULT_GOSSIP_PERIOD_MS())),
             max_transactions_in_block in prop::option::of(Just(Configuration::DEFAULT_MAX_TRANSACTIONS_IN_BLOCK())),
             debug_force_soft_fork in prop::option::of(Just(Configuration::DEFAULT_DEBUG_FORCE_SOFT_FORK())),
            )
            -> ConfigurationBuilder {
            ConfigurationBuilder {
                key_pair,
                peer_id,
                block_time_ms,
                trusted_peers,
                commit_time_limit_ms,
                actor_channel_capacity,
                gossip_batch_size,
                gossip_period_ms,
                max_transactions_in_block,
                #[cfg(debug_assertions)]
                debug_force_soft_fork
            }
        }
    }
}
