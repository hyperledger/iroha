//! Module for `Queue`-related configuration and structs.
#![allow(clippy::std_instead_of_core, clippy::arithmetic)]
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use serde::{Deserialize, Serialize};

const DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK: u32 = 2_u32.pow(9);
const DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE: u32 = 2_u32.pow(16);
// 24 hours
const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 24 * 60 * 60 * 1000;
const DEFAULT_FUTURE_THRESHOLD_MS: u64 = 1000;

/// `Queue` configuration.
#[derive(
    Copy, Clone, Deserialize, Serialize, Debug, Documented, Proxy, LoadFromEnv, PartialEq, Eq,
)]
#[serde(rename_all = "UPPERCASE")]
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

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            maximum_transactions_in_block: Some(DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK),
            maximum_transactions_in_queue: Some(DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE),
            transaction_time_to_live_ms: Some(DEFAULT_TRANSACTION_TIME_TO_LIVE_MS),
            future_threshold_ms: Some(DEFAULT_FUTURE_THRESHOLD_MS),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                maximum_transactions_in_block in prop::option::of(Just(DEFAULT_MAXIMUM_TRANSACTIONS_IN_BLOCK)),
                maximum_transactions_in_queue in prop::option::of(Just(DEFAULT_MAXIMUM_TRANSACTIONS_IN_QUEUE)),
                transaction_time_to_live_ms in prop::option::of(Just(DEFAULT_TRANSACTION_TIME_TO_LIVE_MS)),
                future_threshold_ms in prop::option::of(Just(DEFAULT_FUTURE_THRESHOLD_MS)),
            )
            -> ConfigurationProxy {
            ConfigurationProxy { maximum_transactions_in_block, maximum_transactions_in_queue, transaction_time_to_live_ms, future_threshold_ms }
        }
    }
}
