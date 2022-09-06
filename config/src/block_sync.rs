//! Module for `BlockSynchronizer`-related configuration and structs.
#![allow(clippy::std_instead_of_core)]
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use serde::{Deserialize, Serialize};

const DEFAULT_BLOCK_BATCH_SIZE: u32 = 4;
const DEFAULT_GOSSIP_PERIOD_MS: u64 = 10000;
const DEFAULT_ACTOR_CHANNEL_CAPACITY: u32 = 100;

/// Configuration for `BlockSynchronizer`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Documented, Proxy, LoadFromEnv,
)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "BLOCK_SYNC_")]
pub struct Configuration {
    /// The period of time to wait between sending requests for the latest block.
    pub gossip_period_ms: u64,
    /// The number of blocks that can be sent in one message.
    /// Underlying network (`iroha_network`) should support transferring messages this large.
    pub block_batch_size: u32,
    /// Buffer capacity of actor's MPSC channel
    pub actor_channel_capacity: u32,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            gossip_period_ms: Some(DEFAULT_GOSSIP_PERIOD_MS),
            block_batch_size: Some(DEFAULT_BLOCK_BATCH_SIZE),
            actor_channel_capacity: Some(DEFAULT_ACTOR_CHANNEL_CAPACITY),
        }
    }
}
