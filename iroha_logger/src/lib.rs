//! Module with logger for iroha

use std::sync::atomic::{AtomicBool, Ordering};

use once_cell::sync::Lazy;
pub use tracing::instrument as log;
pub use tracing::Instrument;
pub use tracing::Level;
pub use tracing::{debug, error, info, trace, warn};
pub use tracing::{debug_span, error_span, info_span, trace_span, warn_span};
pub use tracing_futures::Instrument as InstrumentFutures;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;

static LOGGER_SET: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

/// Initializes `Logger` with given `LoggerConfiguration`.
/// After the initialization `log` macros will print with the use of this `Logger`.
pub fn init(configuration: config::LoggerConfiguration) {
    if LOGGER_SET
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        let subscriber = tracing_subscriber::fmt()
            .compact()
            .finish()
            .with(LevelFilter::from(configuration.max_log_level));
        tracing::subscriber::set_global_default(subscriber).expect("Failed to init logger");
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_error::Result;
    use serde::{Deserialize, Serialize};
    use tracing_subscriber::filter::LevelFilter;

    use super::*;

    const DEFAULT_MAX_LOG_LEVEL: LevelEnv = LevelEnv::DEBUG;

    /// Log level for reading from environment and se/deserializing
    #[allow(clippy::clippy::upper_case_acronyms)]
    #[derive(Debug, Deserialize, Serialize, Clone, Copy)]
    pub enum LevelEnv {
        /// Error
        ERROR,
        /// Warn
        WARN,
        /// Info
        INFO,
        /// Debug
        DEBUG,
        /// Trace
        TRACE,
    }

    impl Default for LevelEnv {
        fn default() -> Self {
            DEFAULT_MAX_LOG_LEVEL
        }
    }

    impl From<LevelEnv> for Level {
        fn from(level: LevelEnv) -> Self {
            match level {
                LevelEnv::ERROR => Self::ERROR,
                LevelEnv::TRACE => Self::TRACE,
                LevelEnv::INFO => Self::INFO,
                LevelEnv::DEBUG => Self::DEBUG,
                LevelEnv::WARN => Self::WARN,
            }
        }
    }

    impl From<LevelEnv> for LevelFilter {
        fn from(level: LevelEnv) -> Self {
            Level::from(level).into()
        }
    }

    /// Configuration for `Logger`.
    #[derive(Clone, Deserialize, Serialize, Debug, Copy, Configurable, Default)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    pub struct LoggerConfiguration {
        /// Maximum log level
        #[config(serde_as_str)]
        pub max_log_level: LevelEnv,
    }
}
