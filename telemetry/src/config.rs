#[cfg(feature = "dev-telemetry")]
use std::path::PathBuf;

use iroha_config::derive::Configurable;
use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration parameters container
#[derive(Clone, Default, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "TELEMETRY_")]
pub struct Configuration {
    /// The node's name to be seen on the telemetry
    #[config(serde_as_str)]
    pub name: Option<String>,
    /// The url of the telemetry, e.g., ws://127.0.0.1:8001/submit
    #[config(serde_as_str)]
    pub url: Option<Url>,
    /// The filepath that to write dev-telemetry to
    #[cfg(feature = "dev-telemetry")]
    #[config(serde_as_str)]
    pub file: Option<PathBuf>,
}
