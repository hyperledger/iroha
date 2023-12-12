//! Module containing logic related to spawning a logger from the
//! configuration, as well as run-time reloading of the log-level.
use core::fmt::Debug;

use iroha_config_base::derive::{Documented, Proxy};
pub use iroha_data_model::Level;
#[cfg(feature = "tokio-console")]
use iroha_primitives::addr::{socket_addr, SocketAddr};
use serde::{Deserialize, Serialize};

#[cfg(feature = "tokio-console")]
const DEFAULT_TOKIO_CONSOLE_ADDR: SocketAddr = socket_addr!(127.0.0.1:5555);

/// Convert [`Level`] into [`tracing::Level`]
pub fn into_tracing_level(level: Level) -> tracing::Level {
    match level {
        Level::TRACE => tracing::Level::TRACE,
        Level::DEBUG => tracing::Level::DEBUG,
        Level::INFO => tracing::Level::INFO,
        Level::WARN => tracing::Level::WARN,
        Level::ERROR => tracing::Level::ERROR,
    }
}

/// 'Logger' configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Proxy, Documented)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "LOG_")]
// `tokio_console_addr` is not `Copy`, but warning appears without `tokio-console` feature
#[allow(missing_copy_implementations)]
pub struct Configuration {
    /// Level of logging verbosity
    #[config(serde_as_str)]
    pub level: Level,
    /// Output format
    pub format: Format,
    #[cfg(feature = "tokio-console")]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: SocketAddr,
}

/// Reflects formatters in [`tracing_subscriber::fmt::format`]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// See [`tracing_subscriber::fmt::format::Full`]
    Full,
    /// See [`tracing_subscriber::fmt::format::Compact`]
    Compact,
    /// See [`tracing_subscriber::fmt::format::Pretty`]
    Pretty,
    /// See [`tracing_subscriber::fmt::format::Json`]
    Json,
}

impl Default for Format {
    fn default() -> Self {
        Self::Full
    }
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            level: Some(Level::default()),
            format: Some(Format::default()),
            #[cfg(feature = "tokio-console")]
            tokio_console_addr: Some(DEFAULT_TOKIO_CONSOLE_ADDR),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    #[must_use = "strategies do nothing unless used"]
    pub fn arb_proxy() -> impl proptest::strategy::Strategy<Value = ConfigurationProxy> {
        let strat = (
            (prop::option::of(Just(Level::default()))),
            (prop::option::of(Just(Format::default()))),
            #[cfg(feature = "tokio-console")]
            (prop::option::of(Just(DEFAULT_TOKIO_CONSOLE_ADDR))),
        );
        proptest::strategy::Strategy::prop_map(strat, move |strat| ConfigurationProxy {
            level: strat.0,
            format: strat.1,
            #[cfg(feature = "tokio-console")]
            tokio_console_addr: strat.2,
        })
    }

    #[test]
    fn serialize_pretty_format_in_lowercase() {
        let value = Format::Pretty;
        let actual = serde_json::to_string(&value).unwrap();
        assert_eq!("\"pretty\"", actual);
    }
}
