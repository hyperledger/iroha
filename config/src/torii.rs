//! `Torii` configuration as well as the default values for the URLs used for the main endpoints: `p2p`, `telemetry`, but not `api`.
#![allow(clippy::std_instead_of_core, clippy::arithmetic)]
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use serde::{Deserialize, Serialize};

/// Default socket for p2p communication
pub const DEFAULT_TORII_P2P_ADDR: &str = "127.0.0.1:1337";
/// Default socket for reporting internal status and metrics
pub const DEFAULT_TORII_TELEMETRY_URL: &str = "127.0.0.1:8180";
/// Default maximum size of single transaction
pub const DEFAULT_TORII_MAX_TRANSACTION_SIZE: u32 = 2_u32.pow(15);
/// Default upper bound on `content-length` specified in the HTTP request header
pub const DEFAULT_TORII_MAX_CONTENT_LENGTH: u32 = 2_u32.pow(12) * 4000;

/// Structure that defines the configuration parameters of `Torii` which is the routing module.
/// For example the `p2p_addr`, which is used for consensus and block-synchronisation purposes,
/// as well as `max_transaction_size`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Documented, Proxy, LoadFromEnv)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "TORII_")]
pub struct Configuration {
    /// Torii URL for p2p communication for consensus and block synchronization purposes.
    pub p2p_addr: String,
    /// Torii URL for client API.
    pub api_url: String,
    /// Torii URL for reporting internal status and metrics for administration.
    pub telemetry_url: String,
    /// Maximum number of bytes in raw transaction. Used to prevent from DOS attacks.
    pub max_transaction_size: u32,
    /// Maximum number of bytes in raw message. Used to prevent from DOS attacks.
    pub max_content_len: u32,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            p2p_addr: None,
            api_url: None,
            telemetry_url: None,
            max_transaction_size: Some(DEFAULT_TORII_MAX_TRANSACTION_SIZE),
            max_content_len: Some(DEFAULT_TORII_MAX_CONTENT_LENGTH),
        }
    }
}

pub mod uri {
    //! URI that `Torii` uses to route incoming requests.

    /// Default socket for listening on external requests
    pub const DEFAULT_API_URL: &str = "127.0.0.1:8080";
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
