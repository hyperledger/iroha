//! API for *Runtime Executors*.
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeSet;

use data_model::{executor::Result, ValidationFail};
#[cfg(not(test))]
use data_model::{prelude::*, query::AnyQueryBox, smart_contract::payloads};
use iroha_executor_data_model::{parameter::Parameter, permission::Permission};
use iroha_schema::{Ident, MetaMap};
pub use iroha_smart_contract as smart_contract;
pub use iroha_smart_contract_utils::{debug, encode_with_length_prefix};
#[cfg(not(test))]
use iroha_smart_contract_utils::{decode_with_length_prefix_from_raw, encode_and_execute};
pub use smart_contract::{data_model, stub_getrandom};

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
pub fn get_validate_query_payload() -> payloads::Validate<AnyQueryBox> {
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
            use $crate::smart_contract::ExecuteOnHost as _;

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

/// A convenience to build [`ExecutorDataModel`] from within the executor
#[derive(Debug, Clone)]
pub struct DataModelBuilder {
    parameters: BTreeSet<data_model::parameter::CustomParameter>,
    instructions: BTreeSet<Ident>,
    permissions: BTreeSet<Ident>,
    schema: MetaMap,
}

impl DataModelBuilder {
    /// Constructor
    // we don't need to confuse with `with_default_permissions`
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            parameters: <_>::default(),
            instructions: <_>::default(),
            permissions: <_>::default(),
            schema: <_>::default(),
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

        permission::map_default_permissions!(add_to_schema);

        builder
    }

    /// Define a permission in the data model
    #[must_use]
    pub fn add_parameter<T: Parameter + Into<data_model::parameter::CustomParameter>>(
        mut self,
        param: T,
    ) -> Self {
        T::update_schema_map(&mut self.schema);
        self.parameters.insert(param.into());
        self
    }

    /// Define a type of custom instruction in the data model.
    /// Corresponds to payload of `InstructionBox::Custom`.
    #[must_use]
    pub fn add_instruction<T: iroha_schema::IntoSchema>(mut self) -> Self {
        T::update_schema_map(&mut self.schema);
        self.instructions.insert(T::type_name());
        self
    }

    /// Define a permission in the data model
    #[must_use]
    pub fn add_permission<T: Permission>(mut self) -> Self {
        T::update_schema_map(&mut self.schema);
        self.permissions.insert(T::name());
        self
    }

    /// Remove a permission from the data model
    #[must_use]
    pub fn remove_permission<T: Permission>(mut self) -> Self {
        T::remove_from_schema(&mut self.schema);
        self.permissions.remove(&T::name());
        self
    }

    /// Set the data model of the executor via [`set_data_model`]
    #[cfg(not(test))]
    pub fn build_and_set(self) {
        use iroha_smart_contract::query;

        use crate::smart_contract::ExecuteOnHost as _;

        let all_accounts = query(FindAccounts::new()).execute().unwrap();
        let all_roles = query(FindRoles::new()).execute().unwrap();

        for role in all_roles.into_iter().map(|role| role.unwrap()) {
            for permission in role.permissions() {
                if !self.permissions.contains(permission.name()) {
                    Revoke::role_permission(permission.clone(), role.id().clone())
                        .execute()
                        .unwrap();
                }
            }
        }

        for account in all_accounts.into_iter().map(|account| account.unwrap()) {
            let account_permissions = query(FindPermissionsByAccountId::new(account.id().clone()))
                .execute()
                .unwrap()
                .into_iter();

            for permission in account_permissions.map(|permission| permission.unwrap()) {
                if !self.permissions.contains(permission.name()) {
                    Revoke::account_permission(permission, account.id().clone())
                        .execute()
                        .unwrap();
                }
            }
        }

        set_data_model(&ExecutorDataModel::new(
            self.parameters
                .into_iter()
                .map(|param| (param.id().clone(), param))
                .collect(),
            self.instructions,
            self.permissions,
            serde_json::to_value(&self.schema)
                .expect("INTERNAL BUG: Failed to serialize Executor data model entity")
                .into(),
        ));
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
        entrypoint, Constructor, Validate, ValidateEntrypoints, Visit,
    };
    pub use iroha_smart_contract::prelude::*;

    pub use super::{
        data_model::{executor::Result, visit::Visit, ValidationFail},
        deny, execute, DataModelBuilder, Validate,
    };
}
