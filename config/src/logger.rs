//! Module containing logic related to spawning a logger from the
//! configuration, as well as run-time reloading of the log-level.
#![allow(clippy::std_instead_of_core)]
use core::fmt::Debug;

use derive_more::{Deref, DerefMut};
use iroha_config_base::{
    derive::{Documented, LoadFromEnv, Proxy},
    runtime_upgrades::{handle, ReloadError, ReloadMut},
};
use serde::{Deserialize, Serialize};
use tracing::Subscriber;
use tracing_subscriber::{filter::LevelFilter, reload::Handle};

const TELEMETRY_CAPACITY: u32 = 1000;
const DEFAULT_COMPACT_MODE: bool = false;
const DEFAULT_TERMINAL_COLORS: bool = true;
const DEFAULT_MAX_LOG_LEVEL: Level = Level::INFO;

/// Log level for reading from environment and (de)serializing
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Error
    ERROR,
    /// Warn
    WARN,
    /// Info (Default)
    INFO,
    /// Debug
    DEBUG,
    /// Trace
    TRACE,
}

// TODO: derive when bump version to 1.62
impl Default for Level {
    fn default() -> Self {
        DEFAULT_MAX_LOG_LEVEL
    }
}

impl From<Level> for tracing::Level {
    fn from(level: Level) -> Self {
        match level {
            Level::ERROR => Self::ERROR,
            Level::TRACE => Self::TRACE,
            Level::INFO => Self::INFO,
            Level::DEBUG => Self::DEBUG,
            Level::WARN => Self::WARN,
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
#[derive(Clone, Debug, Serialize, Deserialize, Deref, DerefMut, Default)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SyncLevel(handle::SyncValue<Level, handle::Singleton<Level>>);

impl From<Level> for SyncLevel {
    fn from(level: Level) -> Self {
        Self(level.into())
    }
}

/// 'Logger' configuration.
#[derive(Clone, Deserialize, Serialize, Debug, Proxy, LoadFromEnv, Documented)]
#[serde(rename_all = "UPPERCASE")]
#[serde(default)]
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
    pub log_file_path: Option<std::path::PathBuf>,
    /// Enable ANSI terminal colors for formatted output.
    pub terminal_colors: bool,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            max_log_level: SyncLevel::default(),
            telemetry_capacity: TELEMETRY_CAPACITY,
            compact_mode: DEFAULT_COMPACT_MODE,
            log_file_path: None,
            terminal_colors: DEFAULT_TERMINAL_COLORS,
        }
    }
}
