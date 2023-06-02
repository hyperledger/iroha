//! Package for managing iroha configuration

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
pub use iroha_config_derive::Configuration;
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
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

pub mod derive {
    use serde::Deserialize;
    use thiserror::Error;

    // TODO: use VERGEN to point to LTS reference on LTS branch
    /// Reference to the current Dev branch configuration
    pub static CONFIG_REFERENCE: &str =
        "https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/references/config.md";

    // TODO: deal with `#[serde(skip)]`
    /// Derive `Configurable` and `Proxy` error
    #[derive(Debug, Error, Deserialize)]
    #[allow(clippy::enum_variant_names)]
    pub enum Error {
        /// Used in [`Documented`] trait for wrong query errors
        #[error("Got unknown field: `{}`", .0.join("."))]
        UnknownField(Vec<String>),

        /// Used in [`Documented`] trait for deserialization errors
        /// while retaining field info
        #[error("Failed to (de)serialize the field: {}", .field)]
        #[serde(skip)]
        FieldDeserialization {
            /// Field name (known at compile time)
            field: &'static str,
            /// Serde json error
            #[source]
            error: serde_json::Error,
        },

        /// When a field is missing.
        #[error("Please add `{_0}` to the configuration.")]
        #[serde(skip)]
        MissingField(&'static str),

        /// Key pair creation failed, most likely because the keys don't form a pair
        #[error("Key pair creation failed")]
        Crypto(#[from] iroha_crypto::error::Error),

        // IMO this variant should not exist. If the value is inferred, we should only warn people if the inferred value is different from the provided one.
        /// Inferred field was provided by accident and we don't want it to be provided, because the value is inferred from other fields
        #[error("You should remove the field `{}` as its value is determined by other configuration parameters.", .field)]
        #[serde(skip)]
        ProvidedInferredField {
            /// Field name
            field: &'static str,
            /// Additional message to be added as `color_eyre::suggestion`
            message: &'static str,
        },

        /// Value that is unacceptable to Iroha was encountered when deserializing the config
        #[error("The value {} of {} is wrong. \nPlease change the value.", .value, .field)]
        #[serde(skip)]
        InsaneValue {
            /// The value of the field that's incorrect
            value: String,
            /// Field name that contains invalid value
            field: &'static str,
            /// Additional message to be added as `color_eyre::suggestion`
            message: String,
            // docstring: &'static str,  // TODO: Inline the docstring for easy access
        },

        /// Used in the [`LoadFromDisk`](`crate::proxy::LoadFromDisk`) trait for file read errors
        #[error("Reading file from disk failed.")]
        #[serde(skip)]
        Disk(#[from] std::io::Error),

        /// Used in [`LoadFromDisk`](`crate::proxy::LoadFromDisk`) trait for deserialization errors
        #[error("Deserializing JSON failed")]
        #[serde(skip)]
        Json5(#[from] json5::Error),
    }
}

pub mod runtime_upgrades;

pub mod view {
    //! Module for view related traits and structs

    /// Marker trait to set default value [`IsInstanceHasView::IS_INSTANCE_HAS_VIEW`] to `false`
    pub trait NoView {
        /// [`Self`] doesn't implement [`HasView`]
        const IS_HAS_VIEW: bool = false;
    }

    impl<T> NoView for T {}

    /// Marker traits for types for which views are implemented
    pub trait HasView {}

    /// Wrapper structure used to check if type implements `[HasView]`
    /// If `T` doesn't implement [`HasView`] then
    /// [`NoView::IS_INSTANCE_HAS_VIEW`] (`false`) will be used.
    /// Otherwise [`IsInstanceHasView::IS_INSTANCE_HAS_VIEW`] (`true`)
    /// from `impl` block will shadow `NoView::IS_INSTANCE_HAS_VIEW`
    pub struct IsInstanceHasView<T>(core::marker::PhantomData<T>);

    impl<T: HasView> IsInstanceHasView<T> {
        /// `T` implements trait [`HasView`]
        pub const IS_INSTANCE_HAS_VIEW: bool = true;
    }
}

pub mod proxy {
    //! Module with traits for configuration proxies

    use super::*;

    /// Trait for dynamic and asynchronous configuration via
    /// maintenance endpoint for Rust structures
    pub trait Documented: Serialize + DeserializeOwned {
        /// Error type returned by methods of this trait
        type Error;

        /// Return documentation for all fields in a form of a JSON object
        fn get_docs() -> Value;

        /// Get inner documentation for non-leaf fields
        fn get_inner_docs() -> String;

        /// Return the JSON value of a given field
        ///
        /// # Errors
        /// Fails if field was unknown
        #[inline]
        fn get(&self, field: &'_ str) -> Result<Value, Self::Error> {
            self.get_recursive([field])
        }

        /// Get documentation of a given field
        ///
        /// # Errors
        /// Fails if field was unknown
        #[inline]
        fn get_doc(field: &str) -> Result<Option<String>, Self::Error> {
            Self::get_doc_recursive([field])
        }

        /// Return the JSON value of a given inner field of arbitrary
        /// inner depth
        ///
        /// # Errors
        /// Fails if field was unknown
        fn get_recursive<'tl, T>(&self, inner_field: T) -> Result<Value, Self::Error>
        where
            T: AsRef<[&'tl str]> + Send + 'tl;

        #[allow(single_use_lifetimes)] // Unstable
        /// Get documentation of a given inner field of arbitrary depth
        ///
        /// # Errors
        /// Fails if field was unknown
        fn get_doc_recursive<'tl>(
            field: impl AsRef<[&'tl str]>,
        ) -> Result<Option<String>, Self::Error>;
    }
}
