//! Structures, traits and impls related to *runtime* `Validator`s.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::Constructor;
use getset::Getters;
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::transaction::WasmSmartContract;

#[model]
pub mod model {
    use super::*;

    /// validator that checks if an operation satisfies some conditions.
    ///
    /// Can be used with things like [`Transaction`]s,
    /// [`InstructionExpr`]s, etc.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Constructor,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[allow(clippy::multiple_inherent_impl)]
    #[ffi_type(unsafe {robust})]
    #[serde(transparent)]
    #[repr(transparent)]
    // TODO: Derive with getset once FFI impl is fixed
    //#[getset(get = "pub")]
    pub struct Validator {
        /// WASM code of the validator
        pub wasm: WasmSmartContract,
    }

    // TODO: Client doesn't need structures defined inside this macro. When dynamic linking is
    // implemented use: #[cfg(any(feature = "transparent_api", feature = "ffi_import"))]
}

/// Result type that every validator should return.
pub type Result<T = (), E = crate::ValidationFail> = core::result::Result<T, E>;

/// Migration error type.
pub type MigrationError = String;

/// Result type for a validator's `migrate()` entrypoint.
pub type MigrationResult = Result<(), MigrationError>;

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::Validator;
}
