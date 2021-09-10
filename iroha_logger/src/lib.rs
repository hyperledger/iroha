//! Module with logger for iroha

use std::sync::atomic::{AtomicBool, Ordering};

use color_eyre::Report;
use layer::LevelFilter;
use telemetry::{Telemetry, TelemetryLayer};
use tokio::sync::mpsc::Receiver;
use tracing::subscriber::set_global_default;
pub use tracing::{
    debug, debug_span, error, error_span, info, info_span, instrument as log, trace, trace_span,
    warn, warn_span, Instrument, Level,
};
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
    let level = configuration.max_log_level.into();
    let subscriber_builder = tracing_subscriber::fmt().with_test_writer();
    if configuration.compact_mode {
        let subscriber = subscriber_builder.compact().finish();
        let (subscriber, receiver) = TelemetryLayer::from_capacity(
            LevelFilter::new(level, subscriber),
            configuration.telemetry_capacity,
        );

        #[allow(clippy::expect_used)]
        set_global_default(subscriber).expect("Failed to init logger");
        Some(receiver)
    } else {
        let subscriber = subscriber_builder.finish();
        let (subscriber, receiver) = TelemetryLayer::from_capacity(
            LevelFilter::new(level, subscriber),
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
    #[allow(clippy::upper_case_acronyms)]
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

/// Installs the panic hook with [`color_eyre::install`] if it isn't installed yet
/// # Errors
/// Fails if [`color_eyre::install`] fails
pub fn install_panic_hook() -> Result<(), Report> {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        color_eyre::install()
    } else {
        Ok(())
    }
}
