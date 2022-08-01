//! Package for managing iroha configuration

use eyre::WrapErr;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

pub mod derive {
    //! Modules for `Configurable` entities

    use std::{error::Error as StdError, fmt};

    use derive_more::Display;
    /// Generate view for the type and implement conversion `Type -> View`.
    /// View contains a subset of the fields that the type has.
    ///
    /// Works only with structs.
    // TODO: alter as won't be true after yeeting [`Default`]
    /// Type must implement [`Default`].
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
    ///         // `View` shouldn't have field `b` so we must exclude it.
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
    /// //
    /// //  impl Default for StructureView {
    /// //      fn default() -> Self {
    /// //          Self::from(<Structure as Default>::default())
    /// //      }
    /// //  }
    ///
    ///
    /// let structure = Structure { a: 13, b: 37 };
    /// let view: StructureView = structure.into();
    /// assert_eq!(view.a, 13);
    /// let structure_default = Structure::default();
    /// let view_default = StructureView::default();
    /// assert_eq!(structure_default.a, view_default.a);
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
    // TODO: write doc for new macro
    pub use iroha_config_derive::Proxy;

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

    /// Derive `Configurable` and `Proxy` error
    #[derive(Debug)]
    #[allow(clippy::enum_variant_names)]
    pub enum Error {
        /// Got unknown field
        UnknownField(Vec<String>),
        /// Failed to deserialize or serialize a field
        FieldError(FieldError),
        /// Some of the proxy fields were [`None`] at build stage
        ProxyError(String),
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
                Self::ProxyError(field) => {
                    write!(
                        f,
                        "Proxy structure had at least one uninitialized field: {}",
                        field
                    )
                }
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

pub mod view {
    //! Module for view related traits and structs

    /// Marker trait to set default value `IS_HAS_VIEW` to `false`
    pub trait NoView {
        /// [`Self`] doesn't implement [`HasView`]
        const IS_HAS_VIEW: bool = false;
    }
    impl<T> NoView for T {}

    /// Marker traits for types for which views are implemented  
    pub trait HasView {}

    /// Wrapper structure used to check if type implements `[HasView]`
    /// If `T` doesn't implement [`HasView`] then `NoView::IS_HAS_VIEW` (`false`) will be used
    /// Otherwise `IsHasView::IS_HAS_VIEW` (`true`) from `impl` block will shadow `NoView::IS_HAS_VIEW`  
    pub struct IsHasView<T>(std::marker::PhantomData<T>);

    impl<T: HasView> IsHasView<T> {
        /// `T` implements trait [`HasView`]
        pub const IS_HAS_VIEW: bool = true;
    }
}

pub mod proxy {
    //! Module for configuration proxies' traits

    use super::*;

    /// Pseudo-default trait only used for doc generation
    pub trait DocsDefault {
        fn default() -> Self;
    }

    /// Trait used to convert configs from file and env
    pub trait Combine: Sized + Serialize + DeserializeOwned {
        /// Which type of [`Configuration`] it builds into
        type Target;

        /// Build the config, do the necessary checks
        fn build(self) -> Result<Self::Target, derive::Error>;

        /// If any of the fields in [`other`] are filled, they
        /// override the values of the fields in [`self`].
        fn combine(self, other: Self) -> eyre::Result<Self, eyre::Error>;

        /// Construct [`Self`] from a path-like object.
        ///
        /// # Errors
        /// - File not found.
        /// - File found, but peer configuration parsing failed.
        /// - The length of the array in raw JSON representation is different
        /// from the length of the array in
        /// [`self.sumeragi.trusted_peers.peers`], most likely due to two
        /// (or more) peers having the same public key.
        fn from_path<P: AsRef<Path> + Debug + Clone>(path: P) -> eyre::Result<Self, eyre::Error> {
            let file =
                File::open(&path).wrap_err(format!("Failed to open the config file {:?}", path))?;
            let reader = BufReader::new(file);
            serde_json::from_reader(reader)
                .wrap_err(format!("Failed to deserialize json {:?} from reader", path))
        }

        // fn finalize(&mut self) -> Result<()> {
        //     self.sumeragi.key_pair =
        //         KeyPair::new(self.public_key.clone(), self.private_key.clone())?;
        //     self.sumeragi.peer_id =
        //         iroha_data_model::peer::Id::new(&self.torii.p2p_addr, &self.public_key.clone());

        //     Ok(())
        // }

        /// Load configuration from the environment
        ///
        /// # Errors
        /// Fails if Configuration deserialization fails (e.g. if `TrustedPeers` contains entries with duplicate public keys)
        fn load_environment(&mut self) -> core::result::Result<(), derive::Error>;
    }
}
