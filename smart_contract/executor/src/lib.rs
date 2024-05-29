//! API for *Runtime Executors*.
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;
extern crate self as iroha_executor;

use alloc::collections::BTreeSet;

use data_model::{executor::Result, ValidationFail};
#[cfg(not(test))]
use data_model::{prelude::*, smart_contract::payloads};
pub use iroha_schema::MetaMap;
pub use iroha_smart_contract as smart_contract;
pub use iroha_smart_contract_utils::{debug, encode_with_length_prefix};
#[cfg(not(test))]
use iroha_smart_contract_utils::{decode_with_length_prefix_from_raw, encode_and_execute};
pub use smart_contract::{data_model, parse, stub_getrandom};

pub mod default;
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

/// An error that might occur while converting a data model object (with id and payload)
/// into a native executor type.
///
/// Such objects are [`data_model::prelude::Permission`] and [`data_model::prelude::Parameter`].
#[derive(Debug)]
pub enum TryFromDataModelObjectError {
    /// Unexpected object id
    Id(data_model::prelude::Name),
    /// Failed to deserialize object payload
    Deserialize(serde_json::Error),
}

/// A convenience to build [`ExecutorDataModel`] from within the executor
#[derive(Debug, Clone)]
pub struct DataModelBuilder {
    schema: MetaMap,
    permissions: BTreeSet<prelude::PermissionId>,
}

impl DataModelBuilder {
    /// Constructor
    // we don't need to confuse with `with_default_permissions`
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            schema: <_>::default(),
            permissions: <_>::default(),
        }
    }

    /// Creates a data model with default permissions preset (defined in [`default::permissions`])
    #[must_use]
    pub fn with_default_permissions() -> Self {
        let mut builder = Self::new();

        macro_rules! add_to_schema {
            ($token_ty:ty) => {
                builder = builder.add_permission::<$token_ty>();
            };
        }

        default::permissions::map_default_permissions!(add_to_schema);

        builder
    }

    /// Define a permission in the data model
    #[must_use]
    pub fn add_permission<T: permission::Permission>(mut self) -> Self {
        <T as iroha_schema::IntoSchema>::update_schema_map(&mut self.schema);
        self.permissions.insert(<T as permission::Permission>::id());
        self
    }

    /// Remove a permission from the data model
    #[must_use]
    pub fn remove_permission<T: permission::Permission>(mut self) -> Self {
        <T as iroha_schema::IntoSchema>::remove_from_schema(&mut self.schema);
        self.permissions
            .remove(&<T as permission::Permission>::id());
        self
    }

    /// Set the data model of the executor via [`set_data_model`]
    #[cfg(not(test))]
    pub fn build_and_set(self) {
        set_data_model(&ExecutorDataModel::new(
            self.permissions,
            data_model::JsonString::serialize(&self.schema)
                .expect("schema serialization must not fail"),
        ))
    }
}

/// Executor of Iroha operations
pub trait Validate {
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
        entrypoint, Constructor, Permission, Validate, ValidateEntrypoints, ValidateGrantRevoke,
        Visit,
    };
    pub use iroha_smart_contract::prelude::*;

    pub use super::{
        data_model::{
            executor::{MigrationError, MigrationResult, Result},
            visit::Visit,
            ValidationFail,
        },
        deny, execute,
        permission::Permission as PermissionTrait,
        DataModelBuilder, Validate,
    };
}
