//! Module for `LiveQueryStore`-related configuration and structs.

use std::num::NonZeroU64;

use iroha_config_base::derive::{Documented, Proxy};
use serde::{Deserialize, Serialize};

/// Default max time a query can remain in the store unaccessed
pub static DEFAULT_QUERY_IDLE_TIME_MS: once_cell::sync::Lazy<NonZeroU64> =
    once_cell::sync::Lazy::new(|| NonZeroU64::new(30_000).unwrap());

/// Configuration for `QueryService`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Documented, Proxy)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "LIVE_QUERY_STORE_")]
pub struct Configuration {
    /// Time query can remain in the store if unaccessed
    pub query_idle_time_ms: NonZeroU64,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            query_idle_time_ms: Some(*DEFAULT_QUERY_IDLE_TIME_MS),
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
                query_idle_time_ms in prop::option::of(Just(*DEFAULT_QUERY_IDLE_TIME_MS)),
            )
            -> ConfigurationProxy {
            ConfigurationProxy { query_idle_time_ms }
        }
    }
}
