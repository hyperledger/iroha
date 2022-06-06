#[cfg(feature = "dev-telemetry")]
use std::path::PathBuf;

use iroha_config::derive::Configurable;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::retry_period::RetryPeriod;

/// Configuration parameters container
#[derive(Clone, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
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
    #[cfg(feature = "dev-telemetry")]
    #[config(serde_as_str)]
    pub file: Option<PathBuf>,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            name: None,
            url: None,
            min_retry_period: RetryPeriod::DEFAULT_MIN_RETRY_PERIOD,
            max_retry_delay_exponent: RetryPeriod::DEFAULT_MAX_RETRY_DELAY_EXPONENT,
            #[cfg(feature = "dev-telemetry")]
            file: None,
        }
    }
}

const fn default_min_retry_period() -> u64 {
    RetryPeriod::DEFAULT_MIN_RETRY_PERIOD
}

const fn default_max_retry_delay_exponent() -> u8 {
    RetryPeriod::DEFAULT_MAX_RETRY_DELAY_EXPONENT
}
