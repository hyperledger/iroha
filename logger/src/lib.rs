//! Iroha's logging utilities.
pub mod actor;
pub mod layer;
pub mod telemetry;

use std::{
    fmt::Debug,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
};

use actor::LoggerHandle;
use color_eyre::{eyre::eyre, Report, Result};
use iroha_config::logger::into_tracing_level;
pub use iroha_config::{
    logger::{Format, Level},
    parameters::actual::{DevTelemetry as DevTelemetryConfig, Logger as Config},
};
use tracing::subscriber::set_global_default;
pub use tracing::{
    debug, debug_span, error, error_span, info, info_span, instrument as log, trace, trace_span,
    warn, warn_span, Instrument,
};
pub use tracing_futures::Instrument as InstrumentFutures;
pub use tracing_subscriber::reload::Error as ReloadError;
use tracing_subscriber::{layer::SubscriberExt, registry::Registry, reload};

const TELEMETRY_CAPACITY: usize = 1000;

static LOGGER_SET: AtomicBool = AtomicBool::new(false);

fn try_set_logger() -> Result<()> {
    if LOGGER_SET
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(eyre!("Logger is already set."));
    }
    Ok(())
}

/// Configuration needed for [`init_global`]. It is a little extension of [`Config`].
#[derive(Copy, Clone, Debug)]
pub struct InitConfig {
    base: Config,
    terminal_colors: bool,
}

impl InitConfig {
    /// Create new config from the base logger [`Config`]
    pub fn new(base: Config, terminal_colors: bool) -> Self {
        Self {
            base,
            terminal_colors,
        }
    }
}

/// Initializes the logger globally with given [`Configuration`].
///
/// Returns [`LoggerHandle`] to interact with the logger instance
///
/// Works only once per process, all subsequent invocations will fail.
///
/// For usage in tests consider [`test_logger`].
///
/// # Errors
/// If the logger is already set, raises a generic error.
// TODO: refactor configuration in a way that `terminal_colors` is part of it
//       https://github.com/hyperledger/iroha/issues/3500
pub fn init_global(config: InitConfig) -> Result<LoggerHandle> {
    try_set_logger()?;

    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(config.terminal_colors)
        .with_test_writer();

    match config.base.format {
        Format::Full => step2(config, layer),
        Format::Compact => step2(config, layer.compact()),
        Format::Pretty => step2(config, layer.pretty()),
        Format::Json => step2(config, layer.json()),
    }
}

/// Returns once lazily initialised global logger for testing purposes.
///
/// Log level may be modified via `TEST_LOG_LEVEL` environment variable
///
/// # Panics
/// If [`init_global`] or [`disable_global`] were called first.
pub fn test_logger() -> LoggerHandle {
    static LOGGER: OnceLock<LoggerHandle> = OnceLock::new();

    LOGGER
        .get_or_init(|| {
            // NOTE: if this config should be changed for some specific tests, consider
            // isolating those tests into a separate process and controlling default logger config
            // with ENV vars rather than by extending `test_logger` signature. This will both remain
            // `test_logger` simple and also will emphasise isolation which is necessary anyway in
            // case of singleton mocking (where the logger is the singleton).
            let config = Config {
                level: std::env::var("TEST_LOG_LEVEL")
                    .ok()
                    .and_then(|raw| Level::from_str(&raw).ok())
                    .unwrap_or(Level::DEBUG),
                format: Format::Pretty,
            };

            init_global(InitConfig::new(config, true)).expect(
                "`init_global()` or `disable_global()` should not be called before `test_logger()`",
            )
        })
        .clone()
}

/// Disables the logger globally, so that subsequent calls to [`init_global`] will fail.
///
/// Disabling logger is required in order to generate flamegraphs and flamecharts.
///
/// # Errors
/// If global logger was already initialised/disabled.
pub fn disable_global() -> Result<()> {
    try_set_logger()
}

fn step2<L>(config: InitConfig, layer: L) -> Result<LoggerHandle>
where
    L: tracing_subscriber::Layer<Registry> + Debug + Send + Sync + 'static,
{
    let level: tracing::Level = into_tracing_level(config.base.level);
    let level_filter = tracing_subscriber::filter::LevelFilter::from_level(level);
    let (level_filter, level_filter_handle) = reload::Layer::new(level_filter);
    let subscriber = Registry::default()
        .with(layer)
        .with(level_filter)
        .with(tracing_error::ErrorLayer::default());

    #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
    let subscriber = subscriber.with(console_subscriber::spawn());

    let (subscriber, receiver) = telemetry::Layer::with_capacity(subscriber, TELEMETRY_CAPACITY);
    set_global_default(subscriber)?;

    let handle = LoggerHandle::new(level_filter_handle, receiver);

    Ok(handle)
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

/// Installs the panic hook with [`color_eyre::install`] if it isn't installed yet
///
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

pub mod prelude {
    //! Module with most used items. Needs to be imported when using `log` macro to avoid `tracing` crate dependency

    pub use tracing::{self, debug, error, info, instrument as log, span, trace, warn, Span};
}
