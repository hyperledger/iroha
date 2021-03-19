//! Crate containing iroha macroses

#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]

/// Crate with errors
pub mod error {
    pub use iroha_error::*;
}

/// Trait alias for encode + decode
pub trait Io: parity_scale_codec::Encode + parity_scale_codec::Decode {}
/// Derive macro trait
pub trait IntoContract {}
/// Derive macro trait
pub trait IntoQuery {}
