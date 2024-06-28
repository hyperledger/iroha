//! Structures, traits and impls related to *runtime* `Executor`s.

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use derive_more::{Constructor, Display};
use getset::Getters;
use iroha_data_model_derive::model;
use iroha_primitives::json::JsonString;
use iroha_schema::{Ident, IntoSchema};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::transaction::WasmSmartContract;

#[model]
mod model {
    use super::*;

    /// executor that checks if an operation satisfies some conditions.
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
    pub struct Executor {
        /// WASM code of the executor
        pub wasm: WasmSmartContract,
    }

    /// Executor data model.
    ///
    /// Defined from within the executor, it describes certain structures the executor
    /// works with.
    ///
    /// Executor can define:
    ///
    /// - Permission tokens (see [`crate::permission::Permission`])
    /// - Configuration parameters (see [`crate::parameter::Parameter`])
    #[derive(
        Default,
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Constructor,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
        Display,
    )]
    #[ffi_type]
    #[display(fmt = "{self:?}")]
    pub struct ExecutorDataModel {
        /// Permission tokens supported by the executor.
        ///
        /// These IDs refer to the types in the schema.
        pub permissions: BTreeSet<Ident>,
        /// Type id in the schema.
        /// Corresponds to payload of `InstructionBox::Custom`.
        ///
        /// Note that technically it is not needed
        /// (custom instructions can be used without specifying it),
        /// however it is recommended to set it,
        /// so clients could retrieve it through Iroha API.
        pub custom_instruction: Option<Ident>,
        /// Data model JSON schema, typically produced by [`IntoSchema`].
        pub schema: JsonString,
    }

    // TODO: Client doesn't need structures defined inside this macro. When dynamic linking is
    // implemented use: #[cfg(any(feature = "transparent_api", feature = "ffi_import"))]
}

// TODO: derive `Getters` once FFI impl is fixed
//       currently it fails for all fields
impl ExecutorDataModel {
    /// Getter
    pub fn permissions(&self) -> &BTreeSet<Ident> {
        &self.permissions
    }

    /// Getter
    pub fn schema(&self) -> &JsonString {
        &self.schema
    }
}

/// Result type that every executor should return.
pub type Result<T = (), E = crate::ValidationFail> = core::result::Result<T, E>;

/// Migration error type.
pub type MigrationError = String;

/// Result type for a executor's `migrate()` entrypoint.
pub type MigrationResult = Result<(), MigrationError>;

pub mod prelude {
    //! The prelude re-exports most commonly used traits, structs and macros from this crate.
    pub use super::{Executor, ExecutorDataModel};
}
