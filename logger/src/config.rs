//! Module containing logic related to spawning a logger from the
//! configuration, as well as run-time reloading of the log-level.
use std::fmt::Debug;

use derive_more::{Deref, DerefMut};
use iroha_config::{
    derive::{Configurable, View},
    logger as config,
    runtime_upgrades::{handle, ReloadError, ReloadMut},
};
use iroha_data_model::config::logger::{
    Configuration as PublicConfiguration, Level as PublicLevel,
};
use serde::{Deserialize, Serialize};
use tracing::Subscriber;
use tracing_subscriber::{filter::LevelFilter, reload::Handle};

const TELEMETRY_CAPACITY: u32 = 1000;
const DEFAULT_COMPACT_MODE: bool = false;
const DEFAULT_TERMINAL_COLORS: bool = true;

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

/// Configuration for [`crate`].
#[derive(Clone, Deserialize, Serialize, Debug, Configurable, View)]
#[serde(rename_all = "UPPERCASE")]
#[serde(default)]
#[view(PublicConfiguration)]
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

impl From<PublicLevel> for SyncLevel {
    fn from(level: PublicLevel) -> Self {
        let inner = match level {
            PublicLevel::ERROR => config::Level::ERROR,
            PublicLevel::WARN => config::Level::WARN,
            PublicLevel::INFO => config::Level::INFO,
            PublicLevel::DEBUG => config::Level::DEBUG,
            PublicLevel::TRACE => config::Level::TRACE,
        };
        Self(Level(inner).into())
    }
}

impl From<SyncLevel> for PublicLevel {
    fn from(level: SyncLevel) -> Self {
        let inner: Level = level.value();
        match inner.0 {
            config::Level::ERROR => PublicLevel::ERROR,
            config::Level::WARN => PublicLevel::WARN,
            config::Level::INFO => PublicLevel::INFO,
            config::Level::DEBUG => PublicLevel::DEBUG,
            config::Level::TRACE => PublicLevel::TRACE,
        }
    }
}
