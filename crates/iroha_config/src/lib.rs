//! Iroha configuration and related utilities.

pub use iroha_config_base as base;
use stderrlog::LogLevelNum;
use tracing::log::SetLoggerError;

pub mod client_api;
pub mod kura;
pub mod logger;
pub mod parameters;
pub mod snapshot;

/// Enables tracing of configuration via [`stderrlog`].
/// # Errors
/// See [`stderrlog::StdErrLog::init`] errors.
pub fn enable_tracing() -> Result<(), SetLoggerError> {
    stderrlog::new()
        .module("iroha_config_base")
        .verbosity(LogLevelNum::Trace)
        .init()
}
