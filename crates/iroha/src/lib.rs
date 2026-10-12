//! Rust client library for talking to Iroha over HTTP/WebSocket.
//!
//! This crate exposes the reusable SDK surface used by applications and by the workspace CLI. The
//! `iroha` command-line binary itself is built by the separate `iroha_cli` crate.
mod sdk_mutation_guard;

pub mod account_address;
pub mod account_bootstrap;
pub mod blocking;
pub mod client;
pub mod collections;
pub mod config;
pub mod da;
mod error;
pub mod http;
mod http_default;
pub mod kagemusha_enrollment;
pub mod nexus_app;
pub mod privacy_issuance;
pub mod query;
pub mod secrecy;
#[cfg(feature = "sm")]
pub mod sm;
pub mod sns;
pub mod stream;
pub mod subscriptions;
pub use error::{
    ApiError, ApiErrorDetails, CanonicalDecodeFailure, Error, NativeFinalityDecodeFailure, Result,
    StatusFailureReason, TransactionPreparationError, TransactionSigningError, TransportErrorKind,
};
pub use iroha_crypto as crypto;
pub use iroha_data_model as data_model;
pub use iroha_executor_data_model as executor_data_model;

#[cfg(test)]
mod frame_identity_tests;
