//! `Torii` configuration as well as the default values for the URLs used for the main endpoints: `p2p`, `telemetry`, but not `api`.
#![allow(clippy::std_instead_of_core, clippy::arithmetic_side_effects)]
use iroha_config_base::{Configuration, Documented};
use iroha_primitives::{addr::SocketAddr, socket_addr};
use serde::{Deserialize, Serialize};

/// Structure that defines the configuration parameters of `Torii` which is the routing module.
/// For example the `p2p_addr`, which is used for consensus and block-synchronisation purposes,
/// as well as `max_transaction_size`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
#[serde(try_from = "ConfigurationBuilder")]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "TORII_")]
pub struct Configuration {
    /// Torii address for p2p communication for consensus and block synchronization purposes.
    #[config(serde_as_str)]
    #[config(default = "socket_addr!(127,0,0,1;1337)")]
    p2p_addr: SocketAddr,
    /// Torii address for client API.
    #[config(serde_as_str)]
    #[config(default = "socket_addr!(127,0,0,1;8080)")]
    api_url: SocketAddr,
    /// Torii address for reporting internal status and metrics for administration.
    #[config(serde_as_str)]
    #[config(default = "socket_addr!(127,0,0,1;8180)")]
    telemetry_url: SocketAddr,
    /// Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.
    #[config(default = "2_u32.pow(15)")]
    max_transaction_size: u32,
    /// Maximum number of bytes in raw message. Used to prevent from DOS attacks.
    #[config(default = "2_u32.pow(12) * 4000")]
    max_content_len: u32,
}

pub mod uri {
    //! URI that `Torii` uses to route incoming requests.

    /// Query URI is used to handle incoming Query requests.
    pub const QUERY: &str = "query";
    /// Transaction URI is used to handle incoming ISI requests.
    pub const TRANSACTION: &str = "transaction";
    /// Block URI is used to handle incoming Block requests.
    pub const CONSENSUS: &str = "consensus";
    /// Health URI is used to handle incoming Healthcheck requests.
    pub const HEALTH: &str = "health";
    /// The URI used for block synchronization.
    pub const BLOCK_SYNC: &str = "block/sync";
    /// The web socket uri used to subscribe to block and transactions statuses.
    pub const SUBSCRIPTION: &str = "events";
    /// The web socket uri used to subscribe to blocks stream.
    pub const BLOCKS_STREAM: &str = "block/stream";
    /// Get pending transactions.
    pub const PENDING_TRANSACTIONS: &str = "pending_transactions";
    /// The URI for local config changing inspecting
    pub const CONFIGURATION: &str = "configuration";
    /// URI to report status for administration
    pub const STATUS: &str = "status";
    ///  Metrics URI is used to export metrics according to [Prometheus
    ///  Guidance](https://prometheus.io/docs/instrumenting/writing_exporters/).
    pub const METRICS: &str = "metrics";
    /// URI for retrieving the schema with which Iroha was built.
    pub const SCHEMA: &str = "schema";
    /// URI for getting the API version currently used
    pub const API_VERSION: &str = "api_version";
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                p2p_addr in prop::option::of(Just(Configuration::DEFAULT_P2P_ADDR())),
                api_url in prop::option::of(Just(Configuration::DEFAULT_API_URL())),
                telemetry_url in prop::option::of(Just(Configuration::DEFAULT_TELEMETRY_URL())),
                max_transaction_size in prop::option::of(Just(Configuration::DEFAULT_MAX_TRANSACTION_SIZE())),
                max_content_len in prop::option::of(Just(Configuration::DEFAULT_MAX_CONTENT_LEN())),
            )
            -> ConfigurationBuilder {
            ConfigurationBuilder { p2p_addr, api_url, telemetry_url, max_transaction_size, max_content_len }
        }
    }
}
