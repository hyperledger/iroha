//! Tools to work with file- and environment-based configuration.
//!
//! The main tool here is [`read::ConfigReader`].
//! It is built around these key concepts:
//!
//! - Read config from TOML files;
//! - Identify each configuration parameter by its path in the file;
//! - Parameter might have an environment variable alias, which overwrites value from files;
//! - Parameter might have a default value, applied if nothing was found in files/env.
//!
//! The reader's goal is to:
//!
//! - Give an exhaustive error report if something fails;
//! - Give origins of values for later use in error reports (see [`WithOrigin`]);
//! - Gives traces for debugging purposes (by [`log`] crate).
//!
//! ## Example: raw usage
//!
//! Let's say we want to read the following config:
//!
//! ```toml
//! [foo]
//! bar = "example" # has env alias BAR
//! baz = 42
//! more = { foo = 24 }
//! ```
//!
//! The reading and manual implementation of [`read::ReadConfig`] might look like:
//!
//! ```
//! use iroha_config_base::{
//!     read::{ConfigReader, FinalWrap, ReadConfig},
//!     toml::TomlSource,
//!     WithOrigin,
//! };
//! use serde::Deserialize;
//! use toml::toml;
//!
//! struct Config {
//!     foo_bar: String,
//!     foo_baz: WithOrigin<u8>,
//!     more: Option<More>,
//! }
//!
//! #[derive(Deserialize)]
//! struct More {
//!     foo: u8,
//! }
//!
//! impl ReadConfig for Config {
//!     fn read(reader: &mut ConfigReader) -> FinalWrap<Self> {
//!         let foo_bar = reader
//!             .read_parameter(["foo", "bar"])
//!             .env("BAR")
//!             .value_required()
//!             .finish();
//!
//!         let foo_baz = reader
//!             .read_parameter(["foo", "baz"])
//!             .value_or_else(|| 100)
//!             .finish_with_origin();
//!
//!         let more = reader
//!             .read_parameter(["foo", "more"])
//!             .value_optional()
//!             .finish();
//!
//!         FinalWrap::value_fn(|| Self {
//!             foo_bar: foo_bar.unwrap(),
//!             foo_baz: foo_baz.unwrap(),
//!             more: more.unwrap(),
//!         })
//!     }
//! }
//!
//! let _config = ConfigReader::new()
//!     .with_toml_source(TomlSource::inline(toml! {
//!         [foo]
//!         bar = "example"
//!         baz = 42
//!         more = { foo = 24 }
//!     }))
//!     .read_and_complete::<Config>()
//!     .expect("config is valid");
//! ```
//!
//! ## Example: using macro
//!
//! [`iroha_config_base_derive::ReadConfig`] macro simplifies manual work.
//! The previous example might be simplified as follows:
//!
//! ```
//! use iroha_config_base::{
//!     read::{ConfigReader, ReadConfig},
//!     toml::TomlSource,
//!     ReadConfig, WithOrigin,
//! };
//! use serde::Deserialize;
//! use toml::toml;
//!
//! #[derive(ReadConfig)]
//! struct Config {
//!     #[config(nested)]
//!     foo: Foo,
//! }
//!
//! #[derive(ReadConfig)]
//! struct Foo {
//!     #[config(env = "BAR")]
//!     bar: String,
//!     #[config(default = "100")]
//!     baz: WithOrigin<u8>,
//!     more: Option<More>,
//! }
//!
//! #[derive(Deserialize)]
//! struct More {
//!     foo: u8,
//! }
//!
//! let config = ConfigReader::new()
//!     .with_toml_source(TomlSource::inline(toml! {
//!         [foo]
//!         bar = "bar"
//!     }))
//!     .read_and_complete::<Config>()
//!     .expect("config is valid");
//!
//! assert_eq!(config.foo.bar, "bar");
//! assert_eq!(*config.foo.baz.value(), 100);
//! assert!(config.foo.more.is_none());
//! ```
//!
//! Here we also use nesting.
//!
//! See macro documentation for details.

#![warn(missing_docs)]

pub mod attach;
pub mod env;
pub mod read;
pub mod toml;
pub mod util;

use std::{
    fmt::{Debug, Display, Formatter},
    path::{Path, PathBuf},
};

pub use iroha_config_base_derive::ReadConfig;

use crate::attach::ConfigValueAndOrigin;

/// Config parameter ID, which is a path in config file, e.g. `foo.bar`.
///
/// ```
/// use iroha_config_base::ParameterId;
///
/// let id = ParameterId::from(["foo", "bar"]);
///
/// assert_eq!(format!("{id}"), "foo.bar");
/// ```
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ParameterId {
    segments: Vec<String>,
}

impl Display for ParameterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut print_dot = false;
        for i in &self.segments {
            if print_dot {
                write!(f, ".")?;
            } else {
                print_dot = true;
            }
            write!(f, "{i}")?;
        }
        Ok(())
    }
}

impl Debug for ParameterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ParameterId({self})")
    }
}

impl<P> From<P> for ParameterId
where
    P: IntoIterator,
    <P as IntoIterator>::Item: AsRef<str>,
{
    fn from(value: P) -> Self {
        Self {
            segments: value.into_iter().map(|x| x.as_ref().to_string()).collect(),
        }
    }
}

/// Indicates an origin where the value of a config parameter came from.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum ParameterOrigin {
    /// Value came from a file
    File { id: ParameterId, path: PathBuf },
    /// Value came from an environment variable
    Env { id: ParameterId, var: String },
    /// Value came from some environment variables (see [`read::ReadingParameter::env_custom`])
    EnvUnknown { id: ParameterId },
    /// It is a default value of a parameter
    Default { id: ParameterId },
    /// Custom origin
    Custom { message: String },
}

impl ParameterOrigin {
    /// Construct [`Self::File`]
    pub fn file(id: ParameterId, path: PathBuf) -> Self {
        Self::File { id, path }
    }

    /// Construct [`Self::Env`]
    pub fn env(id: ParameterId, var: String) -> Self {
        Self::Env { var, id }
    }

    /// Construct [`Self::EnvUnknown`]
    pub fn env_unknown(id: ParameterId) -> Self {
        Self::EnvUnknown { id }
    }

    /// Construct [`Self::Default`]
    pub fn default(id: ParameterId) -> Self {
        Self::Default { id }
    }

    /// Construct [`Self::Custom`]
    pub fn custom(message: String) -> Self {
        Self::Custom { message }
    }
}

/// A container with information on where the value came from, in terms of [`ParameterOrigin`]
#[derive(Debug, Clone)]
pub struct WithOrigin<T> {
    value: T,
    origin: ParameterOrigin,
}

impl<T> WithOrigin<T> {
    /// Constructor
    pub fn new(value: T, origin: ParameterOrigin) -> Self {
        Self { value, origin }
    }

    /// Construct, using caller's location as the origin.
    ///
    /// Primarily for testing purposes.
    #[track_caller]
    pub fn inline(value: T) -> Self {
        Self::new(
            value,
            ParameterOrigin::custom(format!("inlined at `{}`", std::panic::Location::caller())),
        )
    }

    /// Borrow the value
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Exclusively borrow the value
    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Extract the value, dropping the origin.
    ///
    /// Use [`Self::into_tuple`] to extract both the value and the origin.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Extract the value and the origin.
    ///
    /// Use [`Self::into_value`] to extract only the value.
    pub fn into_tuple(self) -> (T, ParameterOrigin) {
        (self.value, self.origin)
    }

    /// Borrow the origin
    pub fn origin(&self) -> &ParameterOrigin {
        &self.origin
    }

    /// Construct [`ConfigValueAndOrigin`] attachment to use with [`error_stack::Report::attach_printable`].
    pub fn into_attachment(self) -> ConfigValueAndOrigin<T> {
        ConfigValueAndOrigin::new(self.value, self.origin)
    }

    /// Convert the value with a function
    pub fn map<F, U>(self, fun: F) -> WithOrigin<U>
    where
        F: FnOnce(T) -> U,
    {
        let Self { value, origin } = self;
        WithOrigin {
            value: fun(value),
            origin,
        }
    }
}

impl<T: AsRef<Path>> WithOrigin<T> {
    /// If the origin is [`ParameterOrigin::File`], will resolve the contained path relative to the origin.
    /// Otherwise, will return the value as-is.
    pub fn resolve_relative_path(&self) -> PathBuf {
        match &self.origin {
            ParameterOrigin::File { path, .. } => path
                .parent()
                .expect("if it is a file, it should have a parent path")
                .join(self.value.as_ref()),
            _ => self.value.as_ref().to_path_buf(),
        }
    }
}
