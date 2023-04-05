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
    #[getset(get = "pub")]
    pub struct Validator {
        /// WASM code of the validator
        pub wasm: WasmSmartContract,
    }

    // TODO: Client doesn't need structures defined inside this macro. When dynamic linking is
    // implemented use: #[cfg(any(feature = "_transparent-api", feature = "ffi-import"))]

    /// Boxed version of [`NeedsPermission`]
    #[derive(
        Debug, Display, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize,
    )]
    #[ffi_type]
    pub enum NeedsValidationBox {
        /// [`Transaction`] application operation
        // TODO: Should it not be `VersionedSignedTransaction`?
        Transaction(SignedTransaction),
        /// [`InstructionBox`] execution operation
        Instruction(InstructionBox),
        /// [`QueryBox`] execution operations
        Query(QueryBox),
    }

    /// Validation verdict. All *runtime validators* should return this type.
    ///
    /// All operations are considered to be **valid** unless proven otherwise.
    /// Validators are allowed to either pass an operation to the next validator
    /// or to deny an operation.
    ///
    /// # Note
    ///
    /// There is no `Allow` variant (as well as it isn't a [`Result`] alias)
    /// because `Allow` and `Result` have a wrong connotation and suggest
    /// an incorrect interpretation of validators system.
    ///
    /// All operations are allowed by default.
    /// Validators are checking for operation **incorrectness**, not for operation correctness.
    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Deserialize, Serialize, IntoSchema)]
    #[must_use]
    pub enum Verdict {
        /// Operation is approved to pass to the next validator
        /// or to be executed if there are no more validators
        Pass,
        /// Operation is denied
        Deny(DenialReason),
    }
}

impl Verdict {
    /// Check if [`Verdict`] is [`Pass`].
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    /// Check if [`Verdict`] is [`Deny`].
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }

    /// Returns [`Deny`] if the verdict is [`Deny`], otherwise returns `other`.
    ///
    /// Arguments passed to and are eagerly evaluated;
    /// if you are passing the result of a function call,
    /// it is recommended to use [`and_then`](Verdict::and_then()), which is lazily evaluated.
    ///
    /// [`Deny`]: Verdict::Deny
    pub fn and(self, other: Verdict) -> Verdict {
        match self {
            Verdict::Pass => other,
            Verdict::Deny(_) => self,
        }
    }

    /// Returns [`Deny`] if the verdict is [`Deny`], otherwise calls `f` and returns the result.
    ///
    /// [`Deny`]: Verdict::Deny
    pub fn and_then<F>(self, f: F) -> Verdict
    where
        F: FnOnce() -> Verdict,
    {
        match self {
            Verdict::Pass => f(),
            Verdict::Deny(_) => self,
        }
    }
}

impl From<Verdict> for Result<(), DenialReason> {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Pass => Ok(()),
            Verdict::Deny(reason) => Err(reason),
        }
    }
}

/// Reason for denying the execution of a particular instruction.
pub type DenialReason = String;

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{NeedsValidationBox, Validator, Verdict};
}
