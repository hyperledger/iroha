use crate::{Error, Result};
use std::error::Error as StdError;
use std::fmt::{self, Debug, Display};
use std::ops::{Deref, DerefMut};
use std::result::Result as StdResult;

#[cfg(backtrace)]
use std::backtrace::Backtrace;

/// Type for wrapping any error with specific message
#[derive(Eq, PartialEq)]
pub struct WrappedError<D, E> {
    /// message
    pub msg: D,
    /// error
    pub error: E,
}

impl<D: Display, E> Display for WrappedError<D, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.msg, f)
    }
}

impl<D: Display, E: Debug> Debug for WrappedError<D, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("msg", &format!("\"{}\"", &self.msg))
            .field("source", &self.error)
            .finish()
    }
}

impl<D, E> Deref for WrappedError<D, E> {
    type Target = E;
    fn deref(&self) -> &Self::Target {
        &self.error
    }
}

impl<D, E> DerefMut for WrappedError<D, E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.error
    }
}

impl<D: Display> StdError for WrappedError<D, Error> {
    #[cfg(backtrace)]
    fn backtrace(&self) -> Option<&Backtrace> {
        self.error.inner.backtrace()
    }

    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.error.inner.source()
    }
}

impl<D: Display, E: StdError + 'static> StdError for WrappedError<D, E> {
    #[cfg(backtrace)]
    fn backtrace(&self) -> Option<&Backtrace> {
        self.error.backtrace()
    }

    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.error)
    }
}

/// Trait for wrapping result with some message
#[allow(clippy::missing_errors_doc)]
pub trait WrapErr<T, E> {
    /// Wraps error with message
    fn wrap_err(self, msg: impl Display + Send + Sync + 'static) -> Result<T>;

    /// Wraps error with closure which is lazily called
    fn wrap_err_with<D, F>(self, f: F) -> Result<T>
    where
        D: Display + Send + Sync + 'static,
        F: FnOnce() -> D;
}

impl<T, E: StdError + Send + Sync + 'static> WrapErr<T, E> for StdResult<T, E> {
    fn wrap_err(self, msg: impl Display + Send + Sync + 'static) -> Result<T> {
        match self {
            Ok(t) => Ok(t),
            Err(error) => Err(WrappedError { msg, error }.into()),
        }
    }

    fn wrap_err_with<D, F>(self, f: F) -> Result<T>
    where
        D: Display + Send + Sync + 'static,
        F: FnOnce() -> D,
    {
        match self {
            Ok(t) => Ok(t),
            Err(error) => {
                let msg = f();
                Err(WrappedError { msg, error }.into())
            }
        }
    }
}

impl<T> WrapErr<T, Error> for Result<T> {
    fn wrap_err(self, msg: impl Display + Send + Sync + 'static) -> Result<T> {
        match self {
            Ok(t) => Ok(t),
            Err(error) => Err(error.wrap_err(msg)),
        }
    }

    fn wrap_err_with<D, F>(self, f: F) -> Result<T>
    where
        D: Display + Send + Sync + 'static,
        F: FnOnce() -> D,
    {
        match self {
            Ok(t) => Ok(t),
            Err(error) => Err(error.wrap_err(f())),
        }
    }
}
