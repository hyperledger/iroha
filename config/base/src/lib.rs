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
    ///
    ///
    /// let structure = Structure { a: 13, b: 37 };
    /// let view: StructureView = structure.into();
    /// assert_eq!(view.a, 13);
    /// ```
    pub use iroha_config_derive::view;
    /// Derive macro for implementing the trait
    /// [`iroha_config::base::proxy::Builder`](`crate::proxy::Builder`)
    /// for config structures. Meant to be used on proxy types only, for
    /// details see [`iroha_config::base::derive::Proxy`](`crate::derive::Proxy`).
    ///
    /// # Container attributes
    ///
    /// ## `#[builder(parent = ..)]`
    /// Takes a target type to build into, e.g. for a `ConfigurationProxy`
    /// it would be `Configuration`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_config_base::derive::{Builder, Override, LoadFromEnv};
    /// use iroha_config_base::proxy::Builder as _;
    ///
    /// // Also need `LoadFromEnv` as it owns the `#[config]` attribute
    /// #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, LoadFromEnv, Builder)]
    /// #[builder(parent = Outer)]
    /// struct OuterProxy { #[config(inner)] inner: Option<InnerProxy> }
    ///
    /// #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, LoadFromEnv, Builder, Override)]
    /// #[builder(parent = Inner)]
    /// struct InnerProxy { b: Option<String> }
    ///
    /// #[derive(Debug, PartialEq)]
    /// struct Outer { inner: Inner }
    ///
    /// #[derive(Debug, PartialEq)]
    /// struct Inner { b: String }
    ///
    /// let outer_proxy = OuterProxy { inner: Some(InnerProxy { b: Some("a".to_owned()) })};
    ///
    /// let outer = Outer { inner: Inner { b: "a".to_owned() } };
    ///
    /// assert_eq!(outer, outer_proxy.build().unwrap());
    /// ```
    pub use iroha_config_derive::Builder;
    /// Derive macro for implementing the trait
    /// [`iroha_config::base::proxy::Documented`](`crate::proxy::Documented`)
    /// for config structures.
    ///
    /// Even though this macro doesn't own any attributes, as of now
    /// it relies on the `#[config]` attribute defined by the
    /// [`iroha_config::base::derive::Override`](`crate::derive::Override`)
    /// macro.  As such, `#[config(env_prefix = ...)]` is required for
    /// generating documentation, and `#[config(inner)]` for getting
    /// inner fields recursively.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_config_base::derive::Documented;
    /// use iroha_config_base::proxy::Documented as _;
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Documented)]
    /// struct Outer { #[config(inner)] inner: Inner }
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Documented)]
    /// struct Inner { b: String }
    ///
    /// let outer = Outer { inner: Inner { b: "a".to_owned() }};
    ///
    /// assert_eq!(outer.get_recursive(["inner", "b"]).unwrap(), "a");
    /// ```
    pub use iroha_config_derive::Documented;
    /// Derive macro for implementing the trait
    /// [`iroha_config::base::proxy::LoadFromDisk`](`crate::proxy::LoadFromDisk`)
    /// trait for config structures.
    ///
    /// Meant to be used on proxy types only, for
    /// details see [`iroha_config::base::derive::Proxy`](`crate::derive::Proxy`).
    ///
    /// The trait's only method, `from_path`,
    /// deserializes a JSON config at the provided path into the parent proxy structure,
    /// leaving it empty in case of any error.
    ///
    /// The `ReturnValue` associated type can be
    /// swapped for anything suitable. Currently, the proxy structure is returned
    /// by default.
    pub use iroha_config_derive::LoadFromDisk;
    /// Derive macro for implementing the
    /// [`iroha_config::base::proxy::LoadFromDisk`](`crate::proxy::LoadFromDisk`)
    /// trait for config structures.
    ///
    /// Meant to be used on proxy types only, for
    /// details see [`iroha_config::base::derive::Proxy`](`crate::derive::Proxy`).
    ///
    /// The `ReturnValue` associated type can be
    /// swapped for anything suitable. Currently, the proxy structure is returned
    /// by default.
    ///
    /// # Container attributes
    /// ## `[config(env_prefix)]`
    /// Sets prefix for all the env variables derived from fields in the
    /// corresponding structure.
    ///
    /// ### Example
    ///
    /// ``` rust
    /// use iroha_config_base::derive::LoadFromEnv;
    /// use iroha_config_base::proxy::LoadFromEnv as _;
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, LoadFromEnv)]
    /// #[config(env_prefix = "PREFIXED_")]
    /// struct PrefixedProxy { a: Option<String> }
    ///
    /// std::env::set_var("PREFIXED_A", "B");
    /// let prefixed = PrefixedProxy::from_env();
    /// assert_eq!(prefixed.a.unwrap(), "B");
    /// ```
    ///
    /// # Field attributes
    /// ## `#[config(inner)]`
    /// Tells macro that the structure stores another config inside,
    /// allowing to load it recursively. Moreover, the types that
    /// have this attributes on them should also implement or
    /// derive the [`iroha_config::base::proxy::Override`](`crate::proxy::Override`)
    /// trait.
    ///
    /// ### Example
    ///
    /// ```rust
    /// use iroha_config_base::derive::{Override, LoadFromEnv};
    /// use iroha_config_base::proxy::LoadFromEnv as _;
    ///
    /// #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, LoadFromEnv)]
    /// struct OuterProxy { #[config(inner)] inner: Option<InnerProxy> }
    ///
    /// #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, Override, LoadFromEnv)]
    /// struct InnerProxy { b: Option<String> }
    ///
    /// let mut outer = OuterProxy { inner: Some(InnerProxy { b: Some("a".to_owned()) })};
    ///
    /// std::env::set_var("B", "a");
    /// let env_outer = OuterProxy::from_env();
    ///
    /// assert_eq!(env_outer, outer);
    /// ```
    ///
    /// ## `#[config(serde_as_str)]`
    /// Tells macro to deserialize from env variable as a bare string.
    ///
    /// ### Example
    ///
    /// ```
    /// use iroha_config_base::derive::LoadFromEnv;
    /// use iroha_config_base::proxy::LoadFromEnv;
    /// use std::net::Ipv4Addr;
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, LoadFromEnv)]
    /// struct IpAddrProxy { #[config(serde_as_str)] ip: Option<Ipv4Addr> }
    ///
    /// std::env::set_var("IP", "127.0.0.1");
    /// let ip = IpAddrProxy::from_env();
    /// assert_eq!(ip.ip.unwrap(), Ipv4Addr::new(127, 0, 0, 1));
    /// ```
    pub use iroha_config_derive::LoadFromEnv;
    /// Derive macro for implementing the trait
    /// [`iroha_config::base::proxy::Override`](`crate::proxy::Override`)
    /// for config structures. Given two proxies, consumes them by recursively overloading
    /// fields of [`self`] with fields of [`other`]. Order matters here,
    /// i.e. `self.combine(other)` could yield different results than `other.combine(self)`.
    ///
    /// Meant to be used on proxy types only, for
    /// details see [`iroha_config::base::derive::Proxy`](`crate::derive::Proxy`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_config_base::derive::{Override, LoadFromEnv};
    /// use iroha_config_base::proxy::Override as _;
    ///
    /// #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, Override, LoadFromEnv)]
    /// struct OuterProxy {
    ///     #[config(inner)]
    ///     inner: Option<InnerProxy>,
    ///     a: Option<String>
    /// }
    ///
    /// #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize, Override, LoadFromEnv)]
    /// struct InnerProxy { b: Option<String> }
    ///
    /// let left_outer = OuterProxy {
    ///     inner: Some(InnerProxy { b: Some("a".to_owned()) }),
    ///     a: None
    /// };
    ///
    /// let right_outer = OuterProxy {
    ///     inner: None,
    ///     a: Some("b".to_owned())
    /// };
    ///
    /// let res_outer = OuterProxy {
    ///     inner: Some(InnerProxy { b: Some("a".to_owned()) }),
    ///     a: Some("b".to_owned())
    /// };
    ///
    /// assert_eq!(left_outer.override_with(right_outer), res_outer);
    /// ```
    pub use iroha_config_derive::Override;
    /// Derive macro for implementing the corresponding proxy type
    /// for config structures. Most of the other traits in the
    /// [`iroha_config_base::proxy`](`crate::proxy`) module are
    /// best derived indirectly via this macro. Proxy types serve
    /// as a stand-in for flexible configuration loading either
    /// from environment variables or configuration files. Proxy types also
    /// provide methods to build the initial parent type from them
    /// (via [`iroha_config_base::proxy::Builder`](`crate::proxy::Builder`)
    /// trait) and ways to combine two proxies together (via
    /// [`iroha_config_base::proxy::Override`](`crate::proxy::Override`)).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_config_base::derive::{Documented, Proxy};
    ///
    /// // Need `Documented` here as it owns the `#[config]` attribute
    /// #[derive(serde::Deserialize, serde::Serialize, Documented, Proxy)]
    /// struct Outer { #[config(inner)] inner: Inner }
    ///
    /// #[derive(serde::Deserialize, serde::Serialize, Documented, Proxy)]
    /// struct Inner { b: String }
    ///
    /// // Will generate something like this
    /// // #[derive(Debug, Clone, serde::Deserialize, serde::Serialize,
    /// //   Builder, Override, Documented, LoadFromEnv, LoadFromDisk)]
    /// // #[builder(parent = Outer)]
    /// // struct OuterProxy { #[config(inner)] inner: Option<InnerProxy> }
    ///
    /// // #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize,
    /// //   Builder, Override, Documented, LoadFromEnv, LoadFromDisk)]
    /// // struct InnerProxy { b: Option<String> }
    /// ```
    pub use iroha_config_derive::Proxy;
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
        #[must_use]
        #[inline]
        pub const fn field_error(field: &'static str, error: serde_json::Error) -> Self {
            Self::FieldError(FieldError { field, error })
        }

        /// To be used for [`Self::UnknownField`] variant construction.
        #[inline]
        #[must_use]
        pub fn concat_error_string(field: &[String]) -> String {
            field.join(".")
        }
    }
}

pub mod runtime_upgrades;

#[allow(clippy::module_name_repetitions)]
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
        #[allow(single_use_lifetimes)]
        fn get_doc_recursive<'tl>(
            field: impl AsRef<[&'tl str]>,
        ) -> Result<Option<String>, Self::Error>;
    }

    /// Trait for combining two configuration instances
    pub trait Override: Serialize + DeserializeOwned + Sized {
        /// If any of the fields in `other` are filled, they
        /// override the values of the fields in [`self`].
        #[must_use]
        fn override_with(self, other: Self) -> Self;
    }

    /// Trait for configuration loading and deserialization from
    /// the environment
    pub trait LoadFromEnv: Sized {
        /// The return type. Could be target `Configuration`,
        /// some `Result`, `Option`, or any other type that
        /// wraps a `..Proxy` or `Configuration` type.
        type ReturnValue;

        /// Load configuration from the environment
        ///
        /// # Errors
        /// - Fails if the deserialization of any field fails.
        fn from_env() -> Self::ReturnValue;
    }

    /// Trait for configuration loading and deserialization from disk
    pub trait LoadFromDisk: Sized {
        /// The return type. Could be target `Configuration`,
        /// some `Result`, `Option`, or any other type that
        /// wraps a `..Proxy` or `Configuration` type.
        type ReturnValue;

        /// Construct [`Self`] from a path-like object.
        ///
        /// # Errors
        /// - File not found.
        /// - File found, but peer configuration parsing failed.
        fn from_path<P: AsRef<Path> + Debug + Clone>(path: P) -> Self::ReturnValue;
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
