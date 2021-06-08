//! Module with logger for iroha

use std::sync::atomic::{AtomicBool, Ordering};

use layer::LevelFilter;
use telemetry::{Telemetry, TelemetryLayer};
use tokio::sync::mpsc::Receiver;
pub use tracing::instrument as log;
use tracing::subscriber::set_global_default;
pub use tracing::Instrument;
pub use tracing::Level;
pub use tracing::{debug, error, info, trace, warn};
pub use tracing::{debug_span, error_span, info_span, trace_span, warn_span};
pub use tracing_futures::Instrument as InstrumentFutures;

pub mod layer;
pub mod telemetry;

static LOGGER_SET: AtomicBool = AtomicBool::new(false);

/// Initializes `Logger` with given [`LoggerConfiguration`](`config::LoggerConfiguration`).
/// After the initialization `log` macros will print with the use of this `Logger`.
pub fn init(configuration: config::LoggerConfiguration) -> Option<Receiver<Telemetry>> {
    if LOGGER_SET
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return None;
    }

    if configuration.compact_mode {
        let fmt = tracing_subscriber::fmt().compact().finish();
        let level = configuration.max_log_level.into();
        let (subscriber, receiver) = TelemetryLayer::from_capacity(
            LevelFilter::new(level, fmt),
            configuration.telemetry_capacity,
        );

        #[allow(clippy::expect_used)]
        set_global_default(subscriber).expect("Failed to init logger");
        Some(receiver)
    } else {
        let fmt = tracing_subscriber::fmt().finish();
        let level = configuration.max_log_level.into();
        let (subscriber, receiver) = TelemetryLayer::from_capacity(
            LevelFilter::new(level, fmt),
            configuration.telemetry_capacity,
        );

        #[allow(clippy::expect_used)]
        set_global_default(subscriber).expect("Failed to init logger");
        Some(receiver)
    }
}

/// Macro for sending telemetry info
#[macro_export]
macro_rules! telemetry_target {
    () => {
        concat!("telemetry::", module_path!())
    };
}

/// Macro for sending telemetry info
#[macro_export]
macro_rules! telemetry {
    // All arguments match arms are from info macro
    () => {
        $crate::info!(target: iroha_logger::telemetry_target!(),)
    };
    ($($k:ident).+ = $($field:tt)*) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            $($k).+ = $($field)*
        )
    );
    (?$($k:ident).+ = $($field:tt)*) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            ?$($k).+ = $($field)*
        )
    );
    (%$($k:ident).+ = $($field:tt)*) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            %$($k).+ = $($field)*
        )
    );
    ($($k:ident).+, $($field:tt)*) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            $($k).+, $($field)*
        )
    );
    (?$($k:ident).+, $($field:tt)*) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            ?$($k).+, $($field)*
        )
    );
    (%$($k:ident).+, $($field:tt)*) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            %$($k).+, $($field)*
        )
    );
    (?$($k:ident).+) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            ?$($k).+
        )
    );
    (%$($k:ident).+) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            %$($k).+
        )
    );
    ($($k:ident).+) => (
        $crate::info!(
            target: iroha_logger::telemetry_target!(),
            $($k).+
        )
    );
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
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
    #[derive(Clone, Deserialize, Serialize, Debug, Copy, Configurable)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(default)]
    pub struct LoggerConfiguration {
        /// Maximum log level
        #[config(serde_as_str)]
        pub max_log_level: LevelEnv,
        /// Capacity (or batch size) for telemetry channel
        pub telemetry_capacity: usize,
        /// Compact mode (no spans from telemetry)
        pub compact_mode: bool,
    }

    const TELEMETRY_CAPACITY: usize = 1000;
    const DEFAULT_COMPACT_MODE: bool = false;

    impl Default for LoggerConfiguration {
        fn default() -> Self {
            Self {
                max_log_level: LevelEnv::default(),
                telemetry_capacity: TELEMETRY_CAPACITY,
                compact_mode: DEFAULT_COMPACT_MODE,
            }
        }
    }
}
