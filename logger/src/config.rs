//! Module containing logic related to spawning a logger from the
//! configuration, as well as run-time reloading of the log-level.
use std::fmt::Debug;

use iroha_config::{
    derive::Configurable,
    logger as config,
    runtime_upgrades::{handle, ReloadError, ReloadMut},
};
use serde::{Deserialize, Serialize};
use tracing::Subscriber;
use tracing_subscriber::{filter::LevelFilter, reload::Handle};

const TELEMETRY_CAPACITY: usize = 1000;
const DEFAULT_COMPACT_MODE: bool = false;

/// Log level for reading from environment and (de)serializing
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(transparent)]
pub struct Level(pub config::Level);

impl From<config::Level> for Level {
    fn from(level: config::Level) -> Self {
        Self(level)
    }
}

impl From<Level> for tracing::Level {
    fn from(level: Level) -> Self {
        match level.0 {
            config::Level::ERROR => Self::ERROR,
            config::Level::TRACE => Self::TRACE,
            config::Level::INFO => Self::INFO,
            config::Level::DEBUG => Self::DEBUG,
            config::Level::WARN => Self::WARN,
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

/// Configuration for [`crate`].
#[derive(Clone, Deserialize, Serialize, Debug, Configurable)]
#[serde(rename_all = "UPPERCASE")]
#[serde(default)]
pub struct Configuration {
    /// Maximum log level
    #[config(serde_as_str)]
    pub max_log_level: handle::SyncValue<Level, handle::Singleton<Level>>,
    /// Capacity (or batch size) for telemetry channel
    pub telemetry_capacity: usize,
    /// Compact mode (no spans from telemetry)
    pub compact_mode: bool,
    /// If provided, logs will be copied to said file in the
    /// format readable by [bunyan](https://lib.rs/crates/bunyan)
    pub log_file_path: Option<std::path::PathBuf>,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            max_log_level: handle::SyncValue::default(),
            telemetry_capacity: TELEMETRY_CAPACITY,
            compact_mode: DEFAULT_COMPACT_MODE,
            log_file_path: None,
        }
    }
}
