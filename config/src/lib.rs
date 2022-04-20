//! Package for managing iroha configuration

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

pub mod derive {
    //! Modules with things related with deriving `Configurable`

    use std::{error::Error as StdError, fmt};

    /// Derive macro for implementing [`iroha_config::Configurable`](`crate::Configurable`) for config structures.
    ///
    /// Has several attributes:
    ///
    /// ## `env_prefix`
    /// Sets prefix for env variable
    /// ``` rust
    /// use iroha_config::{Configurable, derive::Configurable};
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Configurable)]
    /// #[config(env_prefix = "PREFIXED_")]
    /// struct Prefixed { a: String }
    ///
    /// std::env::set_var("PREFIXED_A", "B");
    /// let mut prefixed = Prefixed { a: "a".to_owned() };
    /// prefixed.load_environment();
    /// assert_eq!(prefixed.a, "B");
    /// ```
    ///
    /// ## `inner`
    /// Tells macro that structure stores another config inside
    /// ```rust
    /// use iroha_config::{Configurable, derive::Configurable};
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Configurable)]
    /// struct Outer { #[config(inner)] inner: Inner }
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Configurable)]
    /// struct Inner { b: String }
    ///
    /// let outer = Outer { inner: Inner { b: "a".to_owned() }};
    /// assert_eq!(outer.get_recursive(["inner", "b"]).unwrap(), "a");
    /// ```
    ///
    /// ## `serde_as_str`
    /// Tells macro to deserialize from env variable as bare string:
    /// ```
    /// use iroha_config::{Configurable, derive::Configurable};
    /// use std::net::Ipv4Addr;
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Configurable)]
    /// struct IpAddr { #[config(serde_as_str)] ip: Ipv4Addr, }
    ///
    /// std::env::set_var("IP", "127.0.0.1");
    /// let mut ip = IpAddr { ip: Ipv4Addr::new(10, 0, 0, 1) };
    /// ip.load_environment().expect("String loading never fails");
    /// assert_eq!(ip.ip, Ipv4Addr::new(127, 0, 0, 1));
    /// ```
    pub use iroha_config_derive::Configurable;

    /// Error related to deserializing specific field
    #[derive(Debug)]
    pub struct FieldError {
        /// Field name (known at compile time)
        pub field: &'static str,
        /// Serde-json error
        pub error: serde_json::Error,
    }

    impl StdError for FieldError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.error)
        }
    }

    impl fmt::Display for FieldError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Failed to deserialize field {}", self.field)
        }
    }

    /// Derive `Configurable` error
    #[derive(Debug)]
    pub enum Error {
        /// Got unknown field
        UnknownField(Vec<String>),
        /// Failed to deserialize or serialize field
        FieldError(FieldError),
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::UnknownField(field) => {
                    let field = field
                        .iter()
                        .skip(1)
                        .fold(field[0].clone(), |mut prev, suc| {
                            prev += ".";
                            prev += suc;
                            prev
                        });
                    write!(f, "Failed to deserialize: Unknown field {}", field)
                }
                Self::FieldError(_) => write!(f, "Failed to deserialize"),
            }
        }
    }

    impl StdError for Error {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            if let Error::FieldError(field) = self {
                Some(field)
            } else {
                None
            }
        }
    }

    impl Error {
        /// Constructs field error
        pub const fn field_error(field: &'static str, error: serde_json::Error) -> Self {
            Self::FieldError(FieldError { field, error })
        }
    }
}

pub mod runtime_upgrades;

pub mod logger {
    //! Module containing configuration structures for logger

    use serde::{Deserialize, Serialize};

    const DEFAULT_MAX_LOG_LEVEL: Level = Level::INFO;

    /// Log level for reading from environment and (de)serializing
    #[allow(clippy::upper_case_acronyms)]
    #[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Level {
        /// Error
        ERROR,
        /// Warn
        WARN,
        /// Info (Default)
        INFO,
        /// Debug
        DEBUG,
        /// Trace
        TRACE,
    }

    impl Default for Level {
        fn default() -> Self {
            DEFAULT_MAX_LOG_LEVEL
        }
    }
}

/// Trait for dynamic and asynchronous configuration via maintanence endpoint for rust structures
pub trait Configurable: Serialize + DeserializeOwned {
    /// Error type returned by methods of trait
    type Error;

    /// Gets field of structure and returns as json-value
    /// # Errors
    /// Fails if field was unknown
    fn get(&self, field: &'_ str) -> Result<Value, Self::Error> {
        self.get_recursive([field])
    }

    /// Gets inner field of arbitrary inner depth and returns as json-value
    /// # Errors
    /// Fails if field was unknown
    fn get_recursive<'tl, T>(&self, inner_field: T) -> Result<Value, Self::Error>
    where
        T: AsRef<[&'tl str]> + Send + 'tl;

    /// Fails if fails to deserialize from environment
    /// # Errors
    /// Fails if fails to deserialize from environment
    fn load_environment(&mut self) -> Result<(), Self::Error>;

    /// Gets docs of inner field of arbitrary depth
    /// # Errors
    /// Fails if field was unknown
    fn get_doc_recursive<'tl>(
        field: impl AsRef<[&'tl str]>,
    ) -> Result<Option<&'static str>, Self::Error>;

    /// Gets docs of field
    /// # Errors
    /// Fails if field was unknown
    fn get_doc(field: &str) -> Result<Option<&'static str>, Self::Error> {
        Self::get_doc_recursive([field])
    }

    /// Returns documentation for all fields in form of json object
    fn get_docs() -> Value;
}

/// Json config for getting configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum GetConfiguration {
    /// Getting docs of specific field
    ///
    /// Top-level fields must be enclosed in an array (of strings). This array
    /// provides the fully qualified path to the fields.
    ///
    /// # Examples
    ///
    /// To get the top-level configuration docs for `iroha_core::Torii`
    /// `curl -X GET -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"Docs" : ["torii"]} ' -i`
    ///
    /// To get the documentation on the [`Logger::config::Configuration.max_log_level`]
    /// `curl -X GET -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"Docs" : ["logger", "max_log_level"]}' -i`
    Docs(Vec<String>),
    /// Get the original Value of the full configuration.
    Value,
}

/// Message acceptable for `POST` requests to the configuration endpoint.
#[derive(Clone, Debug, Deserialize, Serialize, Copy)]
pub enum PostConfiguration {
    /// Change the maximum logging level of logger.
    ///
    /// # Examples
    /// To silence all logging events that aren't `ERROR`s
    /// `curl -X POST -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"LogLevel": "ERROR"}' -i`
    LogLevel(logger::Level),
}
