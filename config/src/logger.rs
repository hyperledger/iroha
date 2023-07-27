//! Module containing logic related to spawning a logger from the
//! configuration, as well as run-time reloading of the log-level.
#![allow(clippy::std_instead_of_core)]
use core::fmt::Debug;

use derive_more::{Deref, DerefMut, From};
use iroha_config_base::{
    derive::{Documented, Proxy},
    runtime_upgrades::{handle, ReloadError, ReloadMut},
};
use iroha_data_model::Level;
use serde::{Deserialize, Serialize};
use tracing::Subscriber;
use tracing_subscriber::{filter::LevelFilter, reload::Handle};

const TELEMETRY_CAPACITY: u32 = 1000;
const DEFAULT_COMPACT_MODE: bool = false;
const DEFAULT_TERMINAL_COLORS: bool = true;
#[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
const DEFAULT_TOKIO_CONSOLE_ADDR: &str = "127.0.0.1:5555";

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

/// Wrapper for [`Handle`] to implement [`ReloadMut`]
#[derive(From)]
pub struct ReloadHandle<T>(pub Handle<LevelFilter, T>);

impl<T: Subscriber + Debug> ReloadMut<Level> for ReloadHandle<T> {
    fn reload(&mut self, level: Level) -> Result<(), ReloadError> {
        let level_filter =
            tracing_subscriber::filter::LevelFilter::from_level(into_tracing_level(level));

        Handle::reload(&self.0, level_filter).map_err(|err| {
            if err.is_dropped() {
                ReloadError::Dropped
            } else {
                ReloadError::Poisoned
            }
        })
    }
}

/// Wrapper around [`Level`] for runtime upgrades.
#[derive(Debug, Clone, Default, Deref, DerefMut, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SyncLevel(handle::SyncValue<Level, handle::Singleton<Level>>);

impl From<Level> for SyncLevel {
    fn from(level: Level) -> Self {
        Self(level.into())
    }
}

impl PartialEq for SyncLevel {
    fn eq(&self, other: &Self) -> bool {
        self.0.value() == other.0.value()
    }
}

impl Eq for SyncLevel {}

/// 'Logger' configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Proxy, Documented)]
#[serde(rename_all = "UPPERCASE")]
pub struct Configuration {
    /// Maximum log level
    #[config(serde_as_str)]
    pub max_log_level: SyncLevel,
    /// Capacity (or batch size) for telemetry channel
    pub telemetry_capacity: u32,
    /// Compact mode (no spans from telemetry)
    pub compact_mode: bool,
    /// If provided, logs will be copied to said file in the
    /// format readable by [bunyan](https://lib.rs/crates/bunyan)
    #[config(serde_as_str)]
    pub log_file_path: Option<std::path::PathBuf>,
    /// Enable ANSI terminal colors for formatted output.
    pub terminal_colors: bool,
    #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: String,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            max_log_level: Some(SyncLevel::default()),
            telemetry_capacity: Some(TELEMETRY_CAPACITY),
            compact_mode: Some(DEFAULT_COMPACT_MODE),
            log_file_path: Some(None),
            terminal_colors: Some(DEFAULT_TERMINAL_COLORS),
            #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
            tokio_console_addr: Some(DEFAULT_TOKIO_CONSOLE_ADDR.into()),
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
            (prop::option::of(Just(SyncLevel::default()))),
            (prop::option::of(Just(TELEMETRY_CAPACITY))),
            (prop::option::of(Just(DEFAULT_COMPACT_MODE))),
            (prop::option::of(Just(None))),
            (prop::option::of(Just(DEFAULT_TERMINAL_COLORS))),
            #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
            (prop::option::of(Just(DEFAULT_TOKIO_CONSOLE_ADDR.to_string()))),
        );
        proptest::strategy::Strategy::prop_map(strat, move |strat| ConfigurationProxy {
            max_log_level: strat.0,
            telemetry_capacity: strat.1,
            compact_mode: strat.2,
            log_file_path: strat.3,
            terminal_colors: strat.4,
            #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
            tokio_console_addr: strat.5,
        })
    }
}
