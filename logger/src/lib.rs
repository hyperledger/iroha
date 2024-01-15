//! Iroha's logging utilities.
pub mod actor;
pub mod layer;
pub mod telemetry;

use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
};

use actor::LoggerHandle;
use color_eyre::{eyre::eyre, Report, Result};
use iroha_config::parameters::logger::into_tracing_level;
pub use iroha_config::{
    base::Complete as _,
    parameters::logger::{Config, Format, Level, UserLayer as UserConfigLayer},
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
pub fn init_global(configuration: &Config, terminal_colors: bool) -> Result<LoggerHandle> {
    try_set_logger()?;

    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(terminal_colors)
        .with_test_writer();

    match configuration.format {
        Format::Full => step2(configuration, layer),
        Format::Compact => step2(configuration, layer.compact()),
        Format::Pretty => step2(configuration, layer.pretty()),
        Format::Json => step2(configuration, layer.json()),
    }
}

/// Returns once lazily initialised global logger for testing purposes.
///
/// # Panics
/// If [`init_global`] or [`disable_global`] were called first.
#[allow(clippy::needless_update)] // `tokio-console` feature adds additional fields to Configuration
pub fn test_logger() -> LoggerHandle {
    static LOGGER: OnceLock<LoggerHandle> = OnceLock::new();

    LOGGER
        .get_or_init(|| {
            // let mut config =
            // NOTE: if this config should be changed for some specific tests, consider
            // isolating those tests into a separate process and controlling default logger config
            // with ENV vars rather than by extending `test_logger` signature. This will both remain
            // `test_logger` simple and also will emphasise isolation which is necessary anyway in
            // case of singleton mocking (where the logger is the singleton).
            let config = {
                let mut layer = UserConfigLayer::default();
                let _ = layer.level.insert(Level::DEBUG);
                let _ = layer.format.insert(Format::Pretty);
                layer
                    .complete()
                    .expect("should not fail because other fields have defaults")
            };

            init_global(&config, true).expect(
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

fn step2<L>(configuration: &Config, layer: L) -> Result<LoggerHandle>
where
    L: tracing_subscriber::Layer<Registry> + Debug + Send + Sync + 'static,
{
    let level: tracing::Level = into_tracing_level(configuration.level);
    let level_filter = tracing_subscriber::filter::LevelFilter::from_level(level);
    let (level_filter, level_filter_handle) = reload::Layer::new(level_filter);
    let subscriber = Registry::default()
        .with(layer)
        .with(level_filter)
        .with(tracing_error::ErrorLayer::default());

    #[cfg(all(feature = "tokio-console", not(feature = "no-tokio-console")))]
    let subscriber = {
        let console_subscriber = console_subscriber::ConsoleLayer::builder()
            .server_addr(
                configuration
                    .tokio_console_addr
                    .into()
                    .expect("Invalid address for tokio console"),
            )
            .spawn();

        subscriber.with(console_subscriber)
    };
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
