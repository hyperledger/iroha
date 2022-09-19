//! Package for managing iroha configuration
#![allow(clippy::std_instead_of_core)]
use std::{fmt::Debug, path::Path};

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub mod derive {
    //! Derives for configuration entities
    /// Generate view for the type and implement conversion `Type -> View`.
    /// View contains a subset of the fields that the type has.
    ///
    /// Works only with structs.
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
    ///         #[view(into = u64)]
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
    /// assert_eq!(structure_default.a as u64, view_default.a);
    /// ```
    pub use iroha_config_derive::view;
    // TODO: more decoupling needed, still depends on `LoadFromEnv` (https://github.com/hyperledger/iroha/issues/2621)
    /// Derive macro for implementing the trait
    /// [`iroha_config::base::proxy::Documented`](`crate::proxy::Documented`)
    /// for config structures.
    ///
    /// Even though this macro doesn't own any attributes, as of now
    /// it relies on the `#[config]` attribute defined by the
    /// [`iroha_config::base::derive::Combine`](`crate::derive::Combine`)
    /// macro.  As such, `#[config(env_prefix = ...)]` is required for
    /// generating documentation, and `#[config(inner)]` for getting
    /// inner fields recursively.
    ///
    /// ```rust
    /// use iroha_config_base::derive::{LoadFromEnv, Documented};
    /// use iroha_config_base::proxy::{LoadFromEnv as _, Documented as _};
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, LoadFromEnv, Documented)]
    /// struct Outer { #[config(inner)] inner: Inner }
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Documented, LoadFromEnv, Debug, Clone)]
    /// struct Inner { b: String }
    ///
    /// let outer = Outer { inner: Inner { b: "a".to_owned() }};
    ///
    /// assert_eq!(outer.get_recursive(["inner", "b"]).unwrap(), "a");
    /// ```
    pub use iroha_config_derive::Documented;
    /// Derive macro for implementing the
    /// [`iroha_config::base::derive::LoadFromEnv`](`crate::proxy::LoadFromEnv`)
    /// trait for config structures.
    ///
    /// Has several attributes:
    ///
    /// ## `env_prefix`
    /// Sets prefix for env variable
    /// ``` rust
    /// use iroha_config_base::derive::LoadFromEnv;
    /// use iroha_config_base::proxy::LoadFromEnv;
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, LoadFromEnv)]
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
    /// use iroha_config_base::derive::LoadFromEnv;
    /// use iroha_config_base::proxy::LoadFromEnv;
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, LoadFromEnv)]
    /// struct Outer { #[config(inner)] inner: Inner }
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, LoadFromEnv, Debug, Clone)]
    /// struct Inner { b: String }
    ///
    /// let mut outer = Outer { inner: Inner { b: "a".to_owned() }};
    /// // Here inner config will be recursively loaded as well
    /// <Outer as LoadFromEnv>::load_environment(&mut outer);
    /// ```
    ///
    /// ## `serde_as_str`
    /// Tells macro to deserialize from env variable as a bare string:
    /// ```
    /// use iroha_config_base::derive::LoadFromEnv;
    /// use iroha_config_base::proxy::LoadFromEnv;
    /// use std::net::Ipv4Addr;
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, LoadFromEnv)]
    /// struct IpAddr { #[config(serde_as_str)] ip: Ipv4Addr, }
    ///
    /// std::env::set_var("IP", "127.0.0.1");
    /// let mut ip = IpAddr { ip: Ipv4Addr::new(10, 0, 0, 1) };
    /// ip.load_environment().expect("String loading never fails");
    /// assert_eq!(ip.ip, Ipv4Addr::new(127, 0, 0, 1));
    /// ```
    pub use iroha_config_derive::LoadFromEnv;
    // TODO: new docs -- probably better left until last steps
    pub use iroha_config_derive::{Builder, Combine, LoadFromDisk, Proxy};
    use serde::Deserialize;
    use thiserror::Error;

    /// Error related to deserializing specific field
    #[derive(Debug, Error)]
    #[error("Name of the field: {}", .field)]
    pub struct FieldError {
        /// Field name (known at compile time)
        pub field: &'static str,
        /// Serde json error
        #[source]
        pub error: serde_json::Error,
    }

    // TODO: deal with `#[serde(skip)]`
    /// Derive `Configurable` and `Proxy` error
    #[derive(Debug, Error, Deserialize)]
    #[allow(clippy::enum_variant_names)]
    pub enum Error {
        /// Used in [`Documented`] trait for wrong query errors
        #[error("Got unknown field: `{}`", Self::concat_error_string(.0))]
        UnknownField(Vec<String>),
        /// Used in [`Documented`] trait for deserialization errors
        /// while retaining field info
        #[error("Failed to (de)serialize the field: {}", .0.field)]
        #[serde(skip)]
        FieldError(#[from] FieldError),
        /// Used in [`Builder`] trait for build errors
        #[error("Proxy failed at build stage due to: {0}")]
        ProxyBuildError(String),
        /// Used in the [`LoadFromDisk`](`crate::proxy::LoadFromDisk`) trait for file read errors
        #[error("Reading file from disk failed: {0}")]
        #[serde(skip)]
        DiskError(#[from] std::io::Error),
        /// Used in [`LoadFromDisk`](`crate::proxy::LoadFromDisk`) trait for deserialization errors
        #[error("Deserializing JSON failed: {0}")]
        #[serde(skip)]
        SerdeError(#[from] serde_json::Error),
    }

    impl Error {
        /// Construct a field error
        pub const fn field_error(field: &'static str, error: serde_json::Error) -> Self {
            Self::FieldError(FieldError { field, error })
        }

        /// To be used for [`Self::UnknownField`] variant construction.
        #[inline]
        pub fn concat_error_string(field: &[String]) -> String {
            field.join(".")
        }
    }
}

pub mod runtime_upgrades;

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
    pub struct IsHasView<T>(core::marker::PhantomData<T>);

    impl<T: HasView> IsHasView<T> {
        /// `T` implements trait [`HasView`]
        pub const IS_HAS_VIEW: bool = true;
    }
}

pub mod proxy {
    //! Module with traits for configuration proxies

    use super::*;

    /// Trait for dynamic and asynchronous configuration via maintenance endpoint for Rust structures
    pub trait Documented: Serialize + DeserializeOwned {
        /// Error type returned by methods of this trait
        type Error;

        /// Return documentation for all fields in a form of a JSON object
        fn get_docs() -> Value;

        /// Get inner documentation for non-leaf fields
        fn get_inner_docs() -> String;

        /// Return the JSON value of a given field
        /// # Errors
        /// Fails if field was unknown
        #[inline]
        fn get(&self, field: &'_ str) -> Result<Value, Self::Error> {
            self.get_recursive([field])
        }

        /// Get documentation of a given field
        /// # Errors
        /// Fails if field was unknown
        #[inline]
        fn get_doc(field: &str) -> Result<Option<String>, Self::Error> {
            Self::get_doc_recursive([field])
        }

        /// Return the JSON value of a given inner field of arbitrary inner depth
        /// # Errors
        /// Fails if field was unknown
        fn get_recursive<'tl, T>(&self, inner_field: T) -> Result<Value, Self::Error>
        where
            T: AsRef<[&'tl str]> + Send + 'tl;

        /// Get documentation of a given inner field of arbitrary depth
        ///
        /// # Errors
        /// Fails if field was unknown
        fn get_doc_recursive<'tl>(
            field: impl AsRef<[&'tl str]>,
        ) -> Result<Option<String>, Self::Error>;
    }

    /// Trait for configuration loading and deserialization
    pub trait Combine: Serialize + DeserializeOwned + Sized + LoadFromEnv + LoadFromDisk {
        // /// Error type returned by methods of this trait
        // type Error;

        /// If any of the fields in `other` are filled, they
        /// override the values of the fields in [`self`].
        #[must_use]
        fn combine(self, other: Self) -> Self;
    }

    /// Trait for configuration loading and deserialization from
    /// the environment
    pub trait LoadFromEnv {
        /// Error type returned by methods of this trait
        type Error;

        /// Load configuration from the environment
        ///
        /// # Errors
        /// - Fails if the deserialization of any field fails.
        fn load_environment(&mut self) -> Result<(), Self::Error>;
    }

    /// Trait for configuration loading and deserialization from disk
    pub trait LoadFromDisk: Sized {
        /// Error type returned by methods of this trait
        type Error;

        /// Construct [`Self`] from a path-like object.
        ///
        /// # Errors
        /// - File not found.
        /// - File found, but peer configuration parsing failed.
        fn from_path<P: AsRef<Path> + Debug + Clone>(path: P) -> Result<Self, Self::Error>;
    }

    /// Trait for building the final config from a proxy one
    pub trait Builder {
        /// The return type. Could be target `Configuration`,
        /// some `Result`, `Option` as users see fit.
        type ReturnValue;

        /// Construct [`Self::ReturnValue`] from a proxy object.
        fn build(self) -> Self::ReturnValue;
    }

    /// Deserialization helper for proxy fields that wrap an `Option`
    ///
    /// # Errors
    /// When deserialization of the field fails, e.g. it doesn't have
    /// the `Option<Option<T>>`
    #[allow(clippy::option_option)]
    pub fn some_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Some)
    }
}
