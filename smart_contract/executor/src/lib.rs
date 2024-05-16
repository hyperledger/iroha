//! API for *Runtime Executors*.
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;
extern crate self as iroha_executor;

use alloc::collections::BTreeSet;

use data_model::{
    executor::{ExecutorDataModel, Result},
    visit::Visit,
    ValidationFail,
};
#[cfg(not(test))]
use data_model::{prelude::*, smart_contract::payloads};
use iroha_executor::data_model::executor::ExecutorDataModelObject;
pub use iroha_schema::MetaMap;
pub use iroha_smart_contract as smart_contract;
use iroha_smart_contract_utils::debug::DebugExpectExt;
pub use iroha_smart_contract_utils::{debug, encode_with_length_prefix};
#[cfg(not(test))]
use iroha_smart_contract_utils::{decode_with_length_prefix_from_raw, encode_and_execute};
use serde::{de::DeserializeOwned, Serialize};
pub use smart_contract::{data_model, parse, stub_getrandom};

use crate::data_model::JsonString;

pub mod default;
pub mod parameter;
pub mod permission;

pub mod utils {
    //! Crate with utilities for implementing smart contract FFI
    pub use iroha_smart_contract_utils::encode_with_length_prefix;
}

pub mod log {
    //! WASM logging utilities
    pub use iroha_smart_contract_utils::{debug, error, event, info, log::*, trace, warn};
}

/// Get payload for `validate_transaction()` entrypoint.
///
/// # Traps
///
/// Host side will generate a trap if this function was called not from a
/// executor `validate_transaction()` entrypoint.
#[cfg(not(test))]
pub fn get_validate_transaction_payload() -> payloads::Validate<SignedTransaction> {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_validate_transaction_payload()) }
}

/// Get payload for `validate_instruction()` entrypoint.
///
/// # Traps
///
/// Host side will generate a trap if this function was called not from a
/// executor `validate_instruction()` entrypoint.
#[cfg(not(test))]
pub fn get_validate_instruction_payload() -> payloads::Validate<InstructionBox> {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_validate_instruction_payload()) }
}

/// Get payload for `validate_query()` entrypoint.
///
/// # Traps
///
/// Host side will generate a trap if this function was called not from a
/// executor `validate_query()` entrypoint.
#[cfg(not(test))]
pub fn get_validate_query_payload() -> payloads::Validate<QueryBox> {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_validate_query_payload()) }
}

/// Get payload for `migrate()` entrypoint.
///
/// # Traps
///
/// Host side will generate a trap if this function was called not from a
/// executor `migrate()` entrypoint.
#[cfg(not(test))]
pub fn get_migrate_payload() -> payloads::Migrate {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_migrate_payload()) }
}

/// Set new [`ExecutorDataModel`].
///
/// # Errors
///
/// - If execution on Iroha side failed
///
/// # Traps
///
/// Host side will generate a trap if this function was not called from a
/// executor's `migrate()` entrypoint.
#[cfg(not(test))]
pub fn set_data_model(data_model: &ExecutorDataModel) {
    // Safety: - ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { encode_and_execute(&data_model, host::set_data_model) }
}

#[cfg(not(test))]
mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Get payload for `validate_transaction()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_validate_transaction_payload() -> *const u8;

        /// Get payload for `validate_instruction()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_validate_instruction_payload() -> *const u8;

        /// Get payload for `validate_query()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_validate_query_payload() -> *const u8;

        /// Get payload for `migrate()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_migrate_payload() -> *const u8;

        /// Set new [`ExecutorDataModel`].
        pub(super) fn set_data_model(ptr: *const u8, len: usize);
    }
}

/// Execute instruction if verdict is [`Ok`], deny if execution failed and return.
///
/// Convention is that you have no checks left if you decided to execute instruction.
#[macro_export]
macro_rules! execute {
    ($executor:ident, $isi:ident) => {{
        if $executor.verdict().is_ok() {
            if let Err(err) = $isi.execute() {
                $executor.deny(err);
            }
        }

        return;
    }};
}

/// Shortcut for setting verdict to [`Err`] and return.
///
/// Supports [`format!`](alloc::fmt::format) syntax as well as any expression returning [`String`](alloc::string::String).
#[macro_export]
macro_rules! deny {
    ($executor:ident, $l:literal $(,)?) => {{
        #[cfg(debug_assertions)]
        if let Err(_error) = $executor.verdict() {
            unreachable!("Executor already denied");
        }
        $executor.deny($crate::data_model::ValidationFail::NotPermitted(
            ::alloc::fmt::format(::core::format_args!($l)),
        ));
        return;
    }};
    ($executor:ident, $e:expr $(,)?) => {{
        #[cfg(debug_assertions)]
        if let Err(_error) = $executor.verdict() {
            unreachable!("Executor already denied");
        }
        $executor.deny($e);
        return;
    }};
}

/// Convert a type to and from [`ExecutorDataModelObject`].
pub trait ConvertDataModelObject: Serialize + DeserializeOwned {
    /// Target object.
    type Object: ExecutorDataModelObject;

    /// Implementor's type ID as specified in the data model schema.
    fn definition_id() -> <Self::Object as ExecutorDataModelObject>::DefinitionId;

    /// Try to convert an object to the type
    /// # Errors
    /// - If object id doesn't match with type id
    /// - If fails to deserialize object payload into the type
    fn try_from_object(object: &Self::Object) -> Result<Self, ConvertDataModelObjectError> {
        let expected_id = Self::definition_id();

        if *object.object_definition_id() != expected_id {
            return Err(ConvertDataModelObjectError::Id(
                object.object_definition_id().clone().into(),
            ));
        }

        object
            .object_payload()
            .deserialize_to()
            .map_err(ConvertDataModelObjectError::Deserialize)
    }

    /// Convert the type into its object representation
    fn into_object(self) -> Self::Object {
        let id = Self::definition_id();

        let payload = DebugExpectExt::dbg_expect(
            serde_json::to_value(self),
            "failed to serialize concrete data model entity; this is a bug",
        );

        Self::Object::new(id, JsonString::from(&payload))
    }
}

/// An error that might occur while converting an [`ExecutorDataModelObject`]
/// into a native executor type.
#[derive(Debug)]
pub enum ConvertDataModelObjectError {
    /// Unexpected object id
    Id(data_model::prelude::Name),
    /// Failed to deserialize object payload
    Deserialize(serde_json::Error),
}

/// A convenience to build [`ExecutorDataModel`] from within the executor
#[derive(Debug, Clone, Default)]
pub struct DataModelBuilder {
    schema: MetaMap,
    permission_tokens: BTreeSet<prelude::PermissionTokenId>,
    parameters: BTreeSet<prelude::ParameterId>,
}

impl DataModelBuilder {
    /// Constructor
    pub fn new() -> Self {
        Self::default()
    }

    /// Define a permission token in the data model
    pub fn add_permission_token<T: permission::Token>(&mut self) {
        <T as iroha_schema::IntoSchema>::update_schema_map(&mut self.schema);
        self.permission_tokens.insert(T::definition_id());
    }

    /// Remove a permission token from the builder
    pub fn remove_permission_token<T: permission::Token>(&mut self) {
        <T as iroha_schema::IntoSchema>::remove_from_schema(&mut self.schema);
        self.permission_tokens.remove(&T::definition_id());
    }

    /// Adds all tokens defined in [`default::tokens`].
    pub fn extend_with_default_permission_tokens(&mut self) {
        macro_rules! add_to_schema {
            ($token_ty:ty) => {
                self.add_permission_token::<$token_ty>();
            };
        }

        default::tokens::map_token_type!(add_to_schema);
    }

    /// Define a configuration parameter in the data model
    pub fn add_parameter<T: parameter::Parameter>(&mut self) {
        <T as iroha_schema::IntoSchema>::update_schema_map(&mut self.schema);
        self.parameters.insert(T::definition_id());
    }

    /// Serializes into a type that is part of Iroha data model, the type
    /// that the _other_ side (i.e. Iroha, not Executor) can work with.
    /// # Errors
    /// If fails to serialize schema as JSON
    pub fn serialize(self) -> ExecutorDataModel {
        ExecutorDataModel::new(
            // FIXME: reduce extra conversion & allocation
            //        current:  MetaMap -> JsonValue (borrowed) -> JsonString(string)
            //        fixed:    MetaMap -> JsonString(string)
            JsonString::from(
                &serde_json::to_value(self.schema).expect("schema serialization must not fail"),
            ),
            self.permission_tokens,
            self.parameters,
        )
    }
}

/// Executor of Iroha operations
pub trait Validate: Visit {
    /// Executor verdict.
    fn verdict(&self) -> &Result;

    /// Current block height.
    fn block_height(&self) -> u64;

    /// Set executor verdict to deny
    fn deny(&mut self, reason: ValidationFail);
}

pub mod prelude {
    //! Contains useful re-exports

    pub use alloc::vec::Vec;

    pub use iroha_executor_derive::{
        entrypoint, Constructor, Token, Validate, ValidateEntrypoints, ValidateGrantRevoke, Visit,
    };
    pub use iroha_smart_contract::prelude::*;

    pub use super::{
        data_model::{
            executor::{MigrationError, MigrationResult, Result},
            visit::Visit,
            ValidationFail,
        },
        deny, execute, DataModelBuilder, Validate,
    };
}
