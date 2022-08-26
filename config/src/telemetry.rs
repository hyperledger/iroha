//! Module for telemetry-related configuration and structs.
#![allow(clippy::std_instead_of_core)]
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration parameters container
#[derive(Clone, Deserialize, Serialize, Debug, Proxy, LoadFromEnv, Documented, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
#[serde(default)]
#[config(env_prefix = "TELEMETRY_")]
pub struct Configuration {
    /// The node's name to be seen on the telemetry
    #[config(serde_as_str)]
    pub name: Option<String>,
    /// The url of the telemetry, e.g., ws://127.0.0.1:8001/submit
    #[config(serde_as_str)]
    pub url: Option<Url>,
    /// The minimum period of time in seconds to wait before reconnecting
    #[serde(default = "default_min_retry_period")]
    pub min_retry_period: u64,
    /// The maximum exponent of 2 that is used for increasing delay between reconnections
    #[serde(default = "default_max_retry_delay_exponent")]
    pub max_retry_delay_exponent: u8,
    /// The filepath that to write dev-telemetry to
    #[config(serde_as_str)]
    pub file: Option<std::path::PathBuf>,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            name: None,
            url: None,
            min_retry_period: retry_period::DEFAULT_MIN_RETRY_PERIOD,
            max_retry_delay_exponent: retry_period::DEFAULT_MAX_RETRY_DELAY_EXPONENT,
            file: None,
        }
    }
}

const fn default_min_retry_period() -> u64 {
    retry_period::DEFAULT_MIN_RETRY_PERIOD
}

const fn default_max_retry_delay_exponent() -> u8 {
    retry_period::DEFAULT_MAX_RETRY_DELAY_EXPONENT
}

/// `RetryPeriod` configuration
pub mod retry_period {
    /// Default minimal retry period
    pub const DEFAULT_MIN_RETRY_PERIOD: u64 = 1;
    /// Default maximum exponent for the retry delay
    pub const DEFAULT_MAX_RETRY_DELAY_EXPONENT: u8 = 4;
}
