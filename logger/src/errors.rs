//! This module contains error handling and logging primitives.

use crate::{debug, error, warn};

/// Trait used for monadic error logging.
pub trait ErrorLogging {
    /// Log a warning using `self`, return `self`.
    /// Examples:
    /// `some_function_that_returns_error().warn("The error will be logged as a warning")?;`
    fn log_warn(self, message: &str) -> Self;

    /// Log an error using `self`, return `self`.
    /// Examples:
    /// `some_function_that_returns_error().err("The error will be logged as a warning")?;`
    fn log_err(self, message: &str) -> Self;

    /// Log the error as a Debug message.
    /// Examples:
    /// `some_function_that_returns_error().debug("The error will be logged as a warning")?;`
    fn log_debug(self, message: &str) -> Self;

    /// Log the error compactly. Use in case the error is neither handled nor forwarded (e.g. `expect`/`unwrap`)
    fn log(self) -> Self;
}

impl<T, E: std::fmt::Display> ErrorLogging for Result<T, E> {
    fn log_warn(self, message: &str) -> Self {
        if let Err(error) = &self {
            warn!(%error, message);
        }
        self
    }

    fn log_err(self, message: &str) -> Self {
        if let Err(error) = &self {
            error!(%error, message);
        }
        self
    }

    fn log_debug(self, message: &str) -> Self {
        if let Err(error) = &self {
            debug!(%error, message);
        }
        self
    }

    fn log(self) -> Self {
        if let Err(error) = &self {
            error!(%error);
        }
        self
    }
}
