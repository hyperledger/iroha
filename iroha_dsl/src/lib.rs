//! Iroha DSL provides declarative API for Iroha Special Instructions,
//! Queries and other public functions.

#![warn(
    anonymous_parameters,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    private_doc_tests,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    future_incompatible,
    nonstandard_style,
    unsafe_code,
    unused_import_braces,
    unused_results,
    variant_size_differences
)]

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    #[doc(inline)]
    pub use iroha_data_model::prelude::*;
}
