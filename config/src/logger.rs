//! Module containing logic related to spawning a logger from the
//! configuration, as well as run-time reloading of the log-level.
#![allow(clippy::std_instead_of_core)]
use core::fmt::Debug;

use derive_more::{Deref, DerefMut};
use iroha_config_base::{
    runtime_upgrades::{handle, ReloadError, ReloadMut},
    Configuration, Documented,
};
use serde::{Deserialize, Serialize};
use strum::FromRepr;
use tracing::Subscriber;
use tracing_subscriber::{filter::LevelFilter, reload::Handle};

/// Log level for reading from environment and (de)serializing
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, FromRepr,
)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u8)]
pub enum Level {
    /// Trace
    TRACE,
    /// Debug
    DEBUG,
    /// Info (Default)
    #[default]
    INFO,
    /// Warn
    WARN,
    /// Error
    ERROR,
}

impl From<Level> for tracing::Level {
    fn from(level: Level) -> Self {
        match level {
            Level::TRACE => Self::TRACE,
            Level::DEBUG => Self::DEBUG,
            Level::INFO => Self::INFO,
            Level::WARN => Self::WARN,
            Level::ERROR => Self::ERROR,
        }
    }
}

impl<T: Subscriber + Debug> ReloadMut<Level> for Handle<LevelFilter, T> {
    fn reload(&mut self, level: Level) -> Result<(), ReloadError> {
        let level_filter = tracing_subscriber::filter::LevelFilter::from_level(level.into());

        Handle::reload(self, level_filter).map_err(|err| {
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
#[serde(try_from = "ConfigurationBuilder")]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "LOG_")]
pub struct Configuration {
    /// Maximum log level
    #[config(serde_as_str)]
    #[config(default = "SyncLevel::default()")]
    max_level: SyncLevel,
    /// Capacity (or batch size) for telemetry channel
    #[config(default = "1000")]
    telemetry_capacity: u32,
    /// Compact mode (no spans from telemetry)
    #[config(default = "false")]
    compact_mode: bool,
    /// If provided, logs will be copied to said file in the
    /// format readable by [bunyan](https://lib.rs/crates/bunyan)
    #[config(serde_as_str)]
    #[config(default = "None")]
    file_path: Option<std::path::PathBuf>,
    /// Enable ANSI terminal colors for formatted output.
    #[config(default = "true")]
    terminal_colors: bool,
    // TODO: It's not good that structures layout depends on compilation flag
    /// Address of tokio console (only available under "tokio-console" feature)
    #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
    #[config(default = "= "127.0.0.1:5555"")]
    tokio_console_addr: String,
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    #[must_use = "strategies do nothing unless used"]
    pub fn arb_proxy() -> impl proptest::strategy::Strategy<Value = ConfigurationBuilder> {
        let strat = (
            (prop::option::of(Just(Configuration::DEFAULT_MAX_LEVEL()))),
            (prop::option::of(Just(Configuration::DEFAULT_TELEMETRY_CAPACITY()))),
            (prop::option::of(Just(Configuration::DEFAULT_COMPACT_MODE()))),
            (prop::option::of(Just(Configuration::DEFAULT_FILE_PATH()))),
            (prop::option::of(Just(Configuration::DEFAULT_TERMINAL_COLORS()))),
            #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
            (prop::option::of(Just(DEFAULT_TOKIO_CONSOLE_ADDR.to_string()))),
        );
        proptest::strategy::Strategy::prop_map(strat, move |strat| ConfigurationBuilder {
            max_level: strat.0,
            telemetry_capacity: strat.1,
            compact_mode: strat.2,
            file_path: strat.3,
            terminal_colors: strat.4,
            #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
            tokio_console_addr: strat.5,
        })
    }
}
