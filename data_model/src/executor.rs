//! Structures, traits and impls related to *runtime* `Executor`s.

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use derive_more::{Constructor, Display};
use getset::Getters;
use iroha_data_model_derive::model;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{
    parameter::ParameterId, permission::PermissionTokenId, transaction::WasmSmartContract,
    JsonString,
};

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
    /// - Permission tokens (see [`crate::permission::PermissionToken`])
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
        /// Data model JSON schema, typically produced by [`IntoSchema`].
        pub schema: JsonString,
        /// Permission tokens supported by the executor.
        ///
        /// These IDs refer to the types in the schema.
        pub permission_token_ids: BTreeSet<PermissionTokenId>,
        /// Configuration parameters supported by the executor.
        ///
        /// These IDs refer to the types in the schema.
        pub parameter_ids: BTreeSet<ParameterId>,
    }

    // TODO: Client doesn't need structures defined inside this macro. When dynamic linking is
    // implemented use: #[cfg(any(feature = "transparent_api", feature = "ffi_import"))]
}

impl ExecutorDataModel {
    /// Getter
    pub fn schema(&self) -> &JsonString {
        &self.schema
    }

    /// Getter
    pub fn permission_token_ids(&self) -> &BTreeSet<PermissionTokenId> {
        &self.permission_token_ids
    }

    /// Getter
    pub fn parameter_ids(&self) -> &BTreeSet<ParameterId> {
        &self.parameter_ids
    }
}

/// Defines an object that is part of the [`ExecutorDataModel`].
///
/// An object consists of id and payload.
/// ID is a unique type identifier in the executor's data model.
/// Payload is JSON-serialized type structure, according to the type schema.
// TODO: support both JSON and SCALE for payload.
pub trait ExecutorDataModelObject: Sized {
    /// Generic identification
    type DefinitionId: PartialEq + Clone + Into<crate::name::Name>;

    /// Constructor
    fn new(definition_id: Self::DefinitionId, payload: JsonString) -> Self;

    /// Getter for the object id
    fn object_definition_id(&self) -> &Self::DefinitionId;

    /// Getter for the object payload
    fn object_payload(&self) -> &JsonString;
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
