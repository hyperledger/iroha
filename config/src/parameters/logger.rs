//! Module containing logic related to spawning a logger from the
//! configuration, as well as run-time reloading of the log-level.
use core::fmt::Debug;

pub use iroha_data_model::Level;
#[cfg(feature = "tokio-console")]
use iroha_primitives::addr::{socket_addr, SocketAddr};
use serde::{Deserialize, Serialize};

use crate::{Complete, CompleteError, CompleteResult, FromEnvDefaultFallback};

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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
// `tokio_console_addr` is not `Copy`, but warning appears without `tokio-console` feature
#[allow(missing_copy_implementations)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    /// Level of logging verbosity
    pub level: Option<Level>,
    /// Output format
    pub format: Option<Format>,
    #[cfg(feature = "tokio-console")]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: Option<SocketAddr>,
}

#[derive(Debug)]
pub struct Config {
    /// Level of logging verbosity
    pub level: Level,
    /// Output format
    pub format: Format,
    #[cfg(feature = "tokio-console")]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: SocketAddr,
}

/// Reflects formatters in [`tracing_subscriber::fmt::format`]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// See [`tracing_subscriber::fmt::format::Full`]
    #[default]
    Full,
    /// See [`tracing_subscriber::fmt::format::Compact`]
    Compact,
    /// See [`tracing_subscriber::fmt::format::Pretty`]
    Pretty,
    /// See [`tracing_subscriber::fmt::format::Json`]
    Json,
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(Config {
            level: self.level.unwrap_or_default(),
            format: self.format.unwrap_or_default(),
            #[cfg(feature = "tokio-console")]
            tokio_console_addr: self
                .tokio_console_addr
                .unwrap_or_else(|| DEFAULT_TOKIO_CONSOLE_ADDR.clone()),
        })
    }
}

impl FromEnvDefaultFallback for UserLayer {}

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn serialize_pretty_format_in_lowercase() {
        let value = Format::Pretty;
        let actual = serde_json::to_string(&value).unwrap();
        assert_eq!("\"pretty\"", actual);
    }
}
