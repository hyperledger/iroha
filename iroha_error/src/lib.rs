//! Iroha Error crate contains error type similar to anyhow and eyre crates.
//!
//! It has general `Error` type which can wrap any type implementing `std::error::Error`.
//! Also it contains alias `iroha_error::Result<T> = Result<T, iroha_error::Error>`.
//!
//! Example:
//! ```rust
//! # pub trait Deserialize {}
//! #
//! # mod serde_json {
//! #     use super::Deserialize;
//! #     use std::io;
//! #
//! #     pub fn from_str<T: Deserialize>(json: &str) -> io::Result<T> {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # struct ClusterMap;
//! #
//! # impl Deserialize for ClusterMap {}
//! #
//! use iroha_error::Result;
//!
//! fn get_cluster_info() -> Result<ClusterMap> {
//!     let config = std::fs::read_to_string("cluster.json")?;
//!     let map: ClusterMap = serde_json::from_str(&config)?;
//!     Ok(map)
//! }
//! # fn main() {}
//! ```
//!
//! Wrap a lower level errors with some context:
//! ```rust
//! # struct It;
//! #
//! # impl It {
//! #     fn detach(&self) -> Result<()> {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! use iroha_error::{WrapErr, Result};
//!
//! fn main() -> Result<()> {
//!     # return Ok(());
//!     #
//!     # const _: &str = stringify! {
//!     ...
//!     # };
//!     #
//!     # let it = It;
//!     # let path = "./path/to/instrs.json";
//!     #
//!     it.detach().wrap_err("Failed to detach the important thing")?;
//!
//!     let content = std::fs::read(path)
//!         .wrap_err_with(|| format!("Failed to read instrs from {}", path))?;
//!     #
//!     # const _: &str = stringify! {
//!     ...
//!     # };
//!     #
//!     # Ok(())
//! }
//! ```

#![allow(clippy::module_name_repetitions)]

use std::convert::{AsRef, From};
use std::error::Error as StdError;
use std::fmt::{self, Debug, Display};
use std::ops::{Deref, DerefMut};
use std::result::Result as StdResult;

pub use message_error::MessageError;
pub use reporter::{install as install_panic_reporter, Reporter};
pub use wrap_err::{WrapErr, WrappedError};

pub mod reporter;

/// Module with derive macroses
pub mod derive {
    /// Derive macro for enums which implements source and display for it.
    ///
    /// ```rust
    /// #[derive(iroha_error::derive::Error, Debug)]
    /// enum Error {
    ///     #[error("Failed because of reason a")]
    ///     ErrorA,
    ///     // #[source] tells macro to use io::Error as source for this variant
    ///     #[error("Failed during reading file")]
    ///     IOError(#[source] std::io::Error),
    /// }
    /// ```
    pub use iroha_error_macro::Error;
}

mod message_error;
mod wrap_err;

/// Error type similar to `anyhow::Error`, `eyre::Reporter`.
pub struct Error {
    inner: Box<dyn StdError + Send + Sync + 'static>,
}

/// Result type which uses Error
pub type Result<T, E = Error> = StdResult<T, E>;

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, formatter)
    }
}

impl Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.inner, formatter)
    }
}

impl AsRef<dyn StdError + Send + Sync + 'static> for Error {
    fn as_ref(&self) -> &(dyn StdError + Send + Sync + 'static) {
        self.inner.as_ref()
    }
}

impl AsRef<dyn StdError + 'static> for Error {
    fn as_ref(&self) -> &(dyn StdError + 'static) {
        self.inner.as_ref()
    }
}

impl Deref for Error {
    type Target = dyn StdError + Send + Sync + 'static;
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DerefMut for Error {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.inner
    }
}

impl<E: StdError + Send + Sync + 'static> From<E> for Error {
    fn from(error: E) -> Self {
        Self::new(error)
    }
}

impl Error {
    /// Wraps error with message
    pub fn wrap_err(self, msg: impl Display + Send + Sync + 'static) -> Self {
        let error = self;
        WrappedError { msg, error }.into()
    }

    /// Constructs reporter from error
    pub const fn report(self) -> Reporter {
        Reporter(self)
    }

    /// Creates error from message
    pub fn msg(msg: impl Display + Debug + Send + Sync + 'static) -> Self {
        MessageError { msg }.into()
    }

    /// Creates error from another error
    pub fn new(error: impl StdError + Send + Sync + 'static) -> Self {
        let inner = Box::new(error);
        Self { inner }
    }
}

/// Macro for creation of error messages
/// ```rust
/// use iroha_error::{Error, error};
///
/// # stringify!(
/// assert_eq!(error!("x = {}", 2), Error::msg(format!("x = {}", 2)));
/// # );
/// ```
///
#[macro_export]
macro_rules! error(
    ( $x:expr ) => {
        iroha_error::Error::msg($x)
    };
    ( $( $x:expr ),* $(,)* ) => {
        iroha_error::Error::msg(format!($($x,)*))
    };
);
