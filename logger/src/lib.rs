//! Module with logger for iroha

use std::{
    fs::OpenOptions,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use color_eyre::{eyre::WrapErr, Report, Result};
use config::LoggerConfiguration;
use layer::LevelFilter;
use telemetry::{Telemetry, TelemetryLayer};
use tokio::sync::mpsc::Receiver;
pub use tracing::{
    debug, debug_span, error, error_span, info, info_span, instrument as log, trace, trace_span,
    warn, warn_span, Instrument, Level,
};
use tracing::{subscriber::set_global_default, Subscriber};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
pub use tracing_futures::Instrument as InstrumentFutures;
use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt, registry::Registry, Layer};

pub mod layer;
pub mod telemetry;

/// Substrate telemetry
pub type SubstrateTelemetry = Receiver<Telemetry>;
/// Future telemetry
pub type FutureTelemetry = Receiver<Telemetry>;

static LOGGER_SET: AtomicBool = AtomicBool::new(false);

/// Initializes `Logger` with given [`LoggerConfiguration`](`config::LoggerConfiguration`).
/// After the initialization `log` macros will print with the use of this `Logger`.
/// Returns the receiving side of telemetry channels (regular telemetry, future telemetry)
/// # Errors
/// If the logger is already set, raises a generic error.
pub fn init(
    configuration: &LoggerConfiguration,
) -> Result<Option<(SubstrateTelemetry, FutureTelemetry)>> {
    if LOGGER_SET
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return Ok(None);
    }

    if configuration.compact_mode {
        let layer = tracing_subscriber::fmt::layer()
            .with_test_writer()
            .compact(); // This shouldn't be a separate type.
        Ok(Some(add_bunyan(configuration, layer)?))
    } else {
        let layer = tracing_subscriber::fmt::layer().with_test_writer();
        Ok(Some(add_bunyan(configuration, layer)?))
    }
}

fn bunyan_writer_create(destination: PathBuf) -> Result<impl MakeWriter> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(destination)
        .wrap_err("Failed to create or open bunyan logs file")
        .map(Arc::new)
}

fn add_bunyan<L: Layer<Registry> + Send + Sync + 'static>(
    configuration: &LoggerConfiguration,
    layer: L,
) -> Result<(SubstrateTelemetry, FutureTelemetry)> {
    #[allow(clippy::option_if_let_else)]
    if let Some(path) = configuration.log_file_path.clone() {
        let bunyan_layer =
            BunyanFormattingLayer::new("bunyan_layer".into(), bunyan_writer_create(path)?);
        let subscriber = Registry::default()
            .with(layer)
            .with(JsonStorageLayer)
            .with(bunyan_layer);
        Ok(add_telemetry_and_set_default(configuration, subscriber)?)
    } else {
        let subscriber = Registry::default().with(layer);
        Ok(add_telemetry_and_set_default(configuration, subscriber)?)
    }
}

fn add_telemetry_and_set_default<S: Subscriber + Send + Sync + 'static>(
    configuration: &LoggerConfiguration,
    subscriber: S,
) -> Result<(SubstrateTelemetry, FutureTelemetry)> {
    let (subscriber, receiver, receiver_future) = TelemetryLayer::from_capacity(
        LevelFilter::new(configuration.max_log_level.into(), subscriber),
        configuration.telemetry_capacity,
    );

    set_global_default(subscriber)?;
    Ok((receiver, receiver_future))
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

/// Macro for getting telemetry future target
#[macro_export]
macro_rules! telemetry_future_target {
    () => {
        concat!("telemetry_future::", module_path!())
    };
}

/// Macro for sending telemetry future info
#[macro_export]
macro_rules! telemetry_future {
	// All arguments match arms are from info macro
	() => {
		$crate::info!(target: iroha_logger::telemetry_future_target!(),)
	};
	($($k:ident).+ = $($field:tt)*) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
			$($k).+ = $($field)*
		)
	);
	(?$($k:ident).+ = $($field:tt)*) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
			?$($k).+ = $($field)*
		)
	);
	(%$($k:ident).+ = $($field:tt)*) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
			%$($k).+ = $($field)*
		)
	);
	($($k:ident).+, $($field:tt)*) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
			$($k).+, $($field)*
		)
	);
	(?$($k:ident).+, $($field:tt)*) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
			?$($k).+, $($field)*
		)
	);
	(%$($k:ident).+, $($field:tt)*) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
			%$($k).+, $($field)*
		)
	);
	(?$($k:ident).+) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
			?$($k).+
		)
	);
	(%$($k:ident).+) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
			%$($k).+
		)
	);
	($($k:ident).+) => (
		$crate::info!(
			target: iroha_logger::telemetry_future_target!(),
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

    /// Log level for reading from environment and (de)serializing
    #[allow(clippy::upper_case_acronyms)]
    #[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
    #[derive(Clone, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
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
        /// If provided, logs will be copied to said file in the
        /// format readable by [bunyan](https://lib.rs/crates/bunyan)
        pub log_file_path: Option<PathBuf>,
    }

    const TELEMETRY_CAPACITY: usize = 1000;
    const DEFAULT_COMPACT_MODE: bool = false;

    impl Default for LoggerConfiguration {
        fn default() -> Self {
            Self {
                max_log_level: LevelEnv::default(),
                telemetry_capacity: TELEMETRY_CAPACITY,
                compact_mode: DEFAULT_COMPACT_MODE,
                log_file_path: None,
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
