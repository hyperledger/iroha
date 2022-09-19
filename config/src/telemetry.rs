//! Module for telemetry-related configuration and structs.
#![allow(clippy::std_instead_of_core)]
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration parameters container
#[derive(Clone, Deserialize, Serialize, Debug, Proxy, LoadFromEnv, Documented, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "TELEMETRY_")]
pub struct Configuration {
    /// The node's name to be seen on the telemetry
    #[config(serde_as_str)]
    pub name: Option<String>,
    /// The url of the telemetry, e.g., ws://127.0.0.1:8001/submit
    #[config(serde_as_str)]
    pub url: Option<Url>,
    /// The minimum period of time in seconds to wait before reconnecting
    pub min_retry_period: u64,
    /// The maximum exponent of 2 that is used for increasing delay between reconnections
    pub max_retry_delay_exponent: u8,
    /// The filepath that to write dev-telemetry to
    #[config(serde_as_str)]
    pub file: Option<std::path::PathBuf>,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            name: Some(None),
            url: Some(None),
            min_retry_period: Some(retry_period::DEFAULT_MIN_RETRY_PERIOD),
            max_retry_delay_exponent: Some(retry_period::DEFAULT_MAX_RETRY_DELAY_EXPONENT),
            file: Some(None),
        }
    }
}

/// `RetryPeriod` configuration
pub mod retry_period {
    /// Default minimal retry period
    pub const DEFAULT_MIN_RETRY_PERIOD: u64 = 1;
    /// Default maximum exponent for the retry delay
    pub const DEFAULT_MAX_RETRY_DELAY_EXPONENT: u8 = 4;
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                name in prop::option::of(Just(None)),
                url in prop::option::of(Just(None)),
                min_retry_period in prop::option::of(Just(retry_period::DEFAULT_MIN_RETRY_PERIOD)),
                max_retry_delay_exponent in prop::option::of(Just(retry_period::DEFAULT_MAX_RETRY_DELAY_EXPONENT)),
                file in prop::option::of(Just(None)),
            )
            -> ConfigurationProxy {
            ConfigurationProxy { name, url, min_retry_period, max_retry_delay_exponent, file }
        }
    }
}
