//! Package for managing iroha configuration

use std::future::Future;
use std::pin::Pin;

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

pub mod derive {
    //! Modules with things related with deriving `Configurable`

    use std::error::Error as StdError;
    use std::fmt;

    /// Derive macro for implementing [`iroha_config::Configurable`] for config structures.
    ///
    /// Has several attributes:
    ///
    /// ## `env_prefix`
    /// Sets prefix for env variable
    /// ``` rust
    /// # async fn test_itself() {
    /// use iroha_config::{Configurable, derive::Configurable};
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Configurable)]
    /// #[config(env_prefix = "PREFIXED_")]
    /// struct Prefixed { a: String }
    ///
    /// std::env::set_var("PREFIXED_A", "B");
    /// let mut prefixed = Prefixed { a: "a".to_owned() };
    /// prefixed.load_environment().await;
    /// assert_eq!(prefixed.a, "B");
    /// # }
    /// # async_std::task::block_on(test_itself())
    /// ```
    ///
    /// ## `inner`
    /// Tells macro that structure stores another config inside
    /// ```rust
    /// # async fn test_itself() {
    /// use iroha_config::{Configurable, derive::Configurable};
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Configurable)]
    /// struct Outer { #[config(inner)] inner: Inner }
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Configurable)]
    /// struct Inner { b: String }
    ///
    /// let outer = Outer { inner: Inner { b: "a".to_owned() }};
    /// assert_eq!(outer.get_recursive(["inner", "b"]).await.unwrap(), "a");
    /// # }
    /// # async_std::task::block_on(test_itself())
    /// ```
    ///
    /// ## `serde_as_str`
    /// Tells macro to deserialize from env variable as bare string:
    /// ```
    /// # async fn test_itself() {
    /// use iroha_config::{Configurable, derive::Configurable};
    /// use std::net::Ipv4Addr;
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Configurable)]
    /// struct IpAddr { #[config(serde_as_str)] ip: Ipv4Addr, }
    ///
    /// std::env::set_var("IP", "127.0.0.1");
    /// let mut ip = IpAddr { ip: Ipv4Addr::new(10, 0, 0, 1) };
    /// ip.load_environment().await.expect("String loading never fails");
    /// assert_eq!(ip.ip, Ipv4Addr::new(127, 0, 0, 1));
    /// # }
    /// # async_std::task::block_on(test_itself())
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

    /// Derive `Configurable` errror
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

/// Pinned Boxed future with output as T and lifetime 'a
pub type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for dynamic and asynchronous configuration via maintanence endpoint for rust structures
pub trait Configurable: Serialize + DeserializeOwned {
    /// Error type returned by methods of trait
    type Error;

    /// Gets field of structure and returns as json-value
    /// # Errors
    /// Fails if field was unknown
    fn get<'a, 'b>(&'a self, field: &'b str) -> BoxedFuture<'a, Result<Value, Self::Error>>
    where
        'b: 'a,
    {
        Box::pin(self.get_recursive([field]))
    }

    /// Gets inner field of arbitrary inner depth and returns as json-value
    /// # Errors
    /// Fails if field was unknown
    fn get_recursive<'a, 'b, T>(
        &'a self,
        inner_field: T,
    ) -> BoxedFuture<'a, Result<Value, Self::Error>>
    where
        'b: 'a,
        T: AsRef<[&'b str]> + Send + 'b;

    /// Fails if fails to deserialize from environment
    /// # Errors
    /// Fails if fails to deserialize from environment
    fn load_environment(&'_ mut self) -> BoxedFuture<'_, Result<(), Self::Error>>;

    /// Gets docs of inner field of arbitrary depth
    /// # Errors
    /// Fails if field was unknown
    fn get_doc_recursive<'a>(
        field: impl AsRef<[&'a str]>,
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
