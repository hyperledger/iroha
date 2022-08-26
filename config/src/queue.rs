//! Module for `Queue`-related configuration and structs.
#![allow(clippy::std_instead_of_core, clippy::arithmetic)]
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use serde::{Deserialize, Serialize};

const DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 2_u32.pow(13);
const DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE: u32 = 2_u32.pow(16);
// 24 hours
const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 24 * 60 * 60 * 1000;
const DEFAULT_FUTURE_THRESHOLD_MS: u64 = 1000;

/// `Queue` configuration.
#[derive(
    Copy, Clone, Deserialize, Serialize, Debug, Documented, Proxy, LoadFromEnv, PartialEq, Eq,
)]
#[serde(rename_all = "UPPERCASE")]
#[serde(default)]
#[config(env_prefix = "QUEUE_")]
pub struct Configuration {
    /// The upper limit of the number of transactions per block.
    pub maximum_transactions_in_block: u32,
    /// The upper limit of the number of transactions waiting in the queue.
    pub maximum_transactions_in_queue: u32,
    /// The transaction will be dropped after this time if it is still in the queue.
    pub transaction_time_to_live_ms: u64,
    /// The threshold to determine if a transaction has been tampered to have a future timestamp.
    pub future_threshold_ms: u64,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            maximum_transactions_in_block: DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK,
            maximum_transactions_in_queue: DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE,
            transaction_time_to_live_ms: DEFAULT_TRANSACTION_TIME_TO_LIVE_MS,
            future_threshold_ms: DEFAULT_FUTURE_THRESHOLD_MS,
        }
    }
}
