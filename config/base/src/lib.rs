//! Package for managing iroha configuration

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

pub mod derive {
    //! Modules for `Configurable` entities

    use std::{error::Error as StdError, fmt};

    use derive_more::Display;
    /// Generate view for the type and implement conversion `Type -> View`.
    /// View contains a subset of the fields that the type has.
    ///
    /// Works only with structs.
    /// Type must implement `Default`.
    ///
    /// ## Container attributes
    ///
    /// ## Field attributes
    /// ### `#[view(ignore)]`
    /// Marks fields to ignore when converting to view type.
    ///
    /// ### `#[view(into = Ty)]`
    /// Sets view's field type to Ty.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use iroha_config_base::derive::view;
    ///
    /// view! {
    ///     #[derive(Default)]
    ///     struct Structure {
    ///         #[view(type = u64)]
    ///         a: u32,
    ///         // `View` doesn't have field `b` so we must exclude it.
    ///         #[view(ignore)]
    ///         b: u32,
    ///     }
    /// }
    ///
    /// // Will generate something like
    /// // --//-- original struct
    /// //  struct StructureView {
    /// //      a: u64,
    /// //  }
    /// //
    /// //  impl From<Structure> for StructureView {
    /// //      fn from(value: Structure) -> Self {
    /// //          let Structure {
    /// //              a,
    /// //              ..
    /// //          } = value;
    /// //          Self {
    /// //              a: From::<_>::from(a),
    /// //          }
    /// //      }
    /// // }
    ///
    /// let structure = Structure { a: 13, b: 37 };
    /// let view: StructureView = structure.into();
    /// assert_eq!(view.a, 13);
    /// ```
    pub use iroha_config_derive::view;
    /// Derive macro for implementing [`iroha_config::Configurable`](`crate::Configurable`) for config structures.
    ///
    /// Has several attributes:
    ///
    /// ## `env_prefix`
    /// Sets prefix for env variable
    /// ``` rust
    /// use iroha_config_base::{Configurable, derive::Configurable};
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
    /// Tells macro that the structure stores another config inside
    /// ```rust
    /// use iroha_config_base::{Configurable, derive::Configurable};
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
    /// Tells macro to deserialize from env variable as a bare string:
    /// ```
    /// use iroha_config_base::{Configurable, derive::Configurable};
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
    #[derive(Debug, Display)]
    #[display(fmt = "Failed to deserialize the field {field}")]
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

    /// Derive `Configurable` error
    #[derive(Debug)]
    pub enum Error {
        /// Got unknown field
        UnknownField(Vec<String>),
        /// Failed to deserialize or serialize a field
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
        /// Construct a field error
        pub const fn field_error(field: &'static str, error: serde_json::Error) -> Self {
            Self::FieldError(FieldError { field, error })
        }
    }
}

pub mod runtime_upgrades;

/// Trait for dynamic and asynchronous configuration via maintenance endpoint for Rust structures
pub trait Configurable: Serialize + DeserializeOwned {
    /// Error type returned by methods of this trait
    type Error;

    /// Return the JSON value of a given field
    /// # Errors
    /// Fails if field was unknown
    fn get(&self, field: &'_ str) -> Result<Value, Self::Error> {
        self.get_recursive([field])
    }

    /// Return the JSON value of a given inner field of arbitrary inner depth
    /// # Errors
    /// Fails if field was unknown
    fn get_recursive<'tl, T>(&self, inner_field: T) -> Result<Value, Self::Error>
    where
        T: AsRef<[&'tl str]> + Send + 'tl;

    /// Load configuration from the environment
    ///
    /// # Errors
    /// Fails if fails to deserialize from environment
    fn load_environment(&mut self) -> Result<(), Self::Error>;

    /// Get documentation of a given inner field of arbitrary depth
    ///
    /// # Errors
    /// Fails if field was unknown
    fn get_doc_recursive<'tl>(field: impl AsRef<[&'tl str]>)
        -> Result<Option<String>, Self::Error>;

    /// Get documentation of a given field
    /// # Errors
    /// Fails if field was unknown
    fn get_doc(field: &str) -> Result<Option<String>, Self::Error> {
        Self::get_doc_recursive([field])
    }

    /// Return documentation for all fields in a form of a JSON object
    fn get_docs() -> Value;

    /// Get inner documentation for non-leaf fields
    fn get_inner_docs() -> String;
}
