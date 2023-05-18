//! Structures, traits and impls related to *runtime* `Validator`s.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use derive_more::{Constructor, Display};
use getset::Getters;
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{
    isi::InstructionBox,
    query::QueryBox,
    transaction::{SignedTransaction, WasmSmartContract},
    FromVariant,
};

/// Reason for denying the execution of a particular instruction.
pub type DenialReason = String;

/// Validation verdict. All *validators* should return this type.
pub type Verdict = Result<(), DenialReason>;

#[model]
pub mod model {
    use super::*;

    /// validator that checks if an operation satisfies some conditions.
    ///
    /// Can be used with things like [`Transaction`]s,
    /// [`InstructionBox`]s, etc.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
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

    /// Boxed version of [`NeedsPermission`]
    #[derive(
        Debug, Display, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize,
    )]
    #[ffi_type]
    pub enum NeedsValidationBox {
        /// [`Transaction`] application operation
        Transaction(SignedTransaction),
        /// [`InstructionBox`] execution operation
        Instruction(InstructionBox),
        /// [`QueryBox`] execution operations
        Query(QueryBox),
    }
}

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{NeedsValidationBox, Validator, Verdict};
}
