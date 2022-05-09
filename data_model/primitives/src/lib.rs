//! Data primitives used inside Iroha, but not related directly to the
//! blockchain-specific data model.
//!
//! If you need a thin wrapper around a third-party library, so that
//! it can be used in `IntoSchema`, as well as [`parity_scale_codec`]'s
//! `Encode` and `Decode` trait implementations, you should add the
//! wrapper as a submodule to this crate, rather than into
//! `iroha_data_model` directly.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod atomic;
pub mod fixed;
pub mod small;
