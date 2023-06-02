//! Module for telemetry-related configuration and structs.
#![allow(clippy::std_instead_of_core)]
use iroha_config_base::{Configuration, Documented};
use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration parameters container
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Documented, Configuration)]
#[serde(try_from = "ConfigurationBuilder")]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "TELEMETRY_")]
pub struct Configuration {
    /// The node's name to be seen on the telemetry
    #[config(serde_as_str)]
    #[config(default = "None")]
    name: Option<String>,
    /// The url of the telemetry, e.g., ws://127.0.0.1:8001/submit
    #[config(serde_as_str)]
    #[config(default = "None")]
    url: Option<Url>,
    /// The minimum period of time in seconds to wait before reconnecting
    #[config(default = "1")]
    min_retry_period: u64,
    /// The maximum exponent of 2 that is used for increasing delay between reconnections
    #[config(default = "4")]
    max_retry_delay_exponent: u8,
    /// The filepath that to write dev-telemetry to
    #[config(serde_as_str)]
    #[config(default = "None")]
    file: Option<std::path::PathBuf>,
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    prop_compose! {
        pub fn arb_proxy()
            (
                name in prop::option::of(Just(Configuration::DEFAULT_NAME())),
                url in prop::option::of(Just(Configuration::DEFAULT_URL())),
                min_retry_period in prop::option::of(Just(Configuration::DEFAULT_MIN_RETRY_PERIOD())),
                max_retry_delay_exponent in prop::option::of(Just(Configuration::DEFAULT_MAX_RETRY_DELAY_EXPONENT())),
                file in prop::option::of(Just(Configuration::DEFAULT_FILE())),
            )
            -> ConfigurationBuilder {
            ConfigurationBuilder { name, url, min_retry_period, max_retry_delay_exponent, file }
        }
    }
}
