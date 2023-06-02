//! Module for `BlockSynchronizer`-related configuration and structs.
use iroha_config_base::{Configuration, Documented};
use serde::{Deserialize, Serialize};

/// Configuration for `BlockSynchronizer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
#[serde(try_from = "ConfigurationBuilder")]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "BLOCK_SYNC_")]
pub struct Configuration {
    /// The period of time to wait between sending requests for the latest block.
    #[config(default = "10000")]
    gossip_period_ms: u64,
    /// The number of blocks that can be sent in one message.
    /// Underlying network (`iroha_network`) should support transferring messages this large.
    #[config(default = "4")]
    block_batch_size: u32,
    /// Buffer capacity of actor's MPSC channel
    #[deprecated]
    #[config(default = "100")]
    actor_channel_capacity: u32,
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                gossip_period_ms in prop::option::of(Just(Configuration::DEFAULT_GOSSIP_PERIOD_MS())),
                block_batch_size in prop::option::of(Just(Configuration::DEFAULT_BLOCK_BATCH_SIZE())),
                actor_channel_capacity in prop::option::of(Just(Configuration::DEFAULT_ACTOR_CHANNEL_CAPACITY())),
            )
            -> ConfigurationBuilder {
            ConfigurationBuilder { gossip_period_ms, block_batch_size, actor_channel_capacity }
        }
    }
}
