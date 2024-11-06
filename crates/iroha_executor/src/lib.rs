//! API for *Runtime Executors*.
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeSet;

use data_model::{executor::Result, ValidationFail};
#[cfg(not(test))]
use data_model::{prelude::*, query::AnyQueryBox, smart_contract::payloads};
use iroha_executor_data_model::{parameter::Parameter, permission::Permission};
pub use iroha_executor_derive::{entrypoint, migrate};
use iroha_schema::{Ident, MetaMap};
pub use iroha_smart_contract as smart_contract;
pub use iroha_smart_contract_utils::{dbg, dbg_panic, DebugExpectExt, DebugUnwrapExt};
pub use smart_contract::{data_model, Iroha};

pub mod default;
pub mod permission;

pub mod log {
    //! WASM logging utilities
    pub use iroha_smart_contract_utils::{debug, error, event, info, trace, warn};
}

#[doc(hidden)]
pub mod utils {
    //! Crate with utilities

    #[cfg(not(test))]
    use iroha_smart_contract_utils::decode_with_length_prefix_from_raw;
    pub use iroha_smart_contract_utils::{
        encode_with_length_prefix, register_getrandom_err_callback,
    };

    #[cfg(not(test))]
    use super::*;

    /// Get context for `validate_transaction()` entrypoint.
    ///
    /// # Safety
    ///
    /// It's safe to call this function as long as it's safe to construct, from the given
    /// pointer, byte array of prefix length and `Box<[u8]>` containing the encoded object
    #[doc(hidden)]
    #[cfg(not(test))]
    pub unsafe fn __decode_execute_transaction_context(
        context: *const u8,
    ) -> payloads::Validate<SignedTransaction> {
        decode_with_length_prefix_from_raw(context)
    }

    /// Get context for `validate_instruction()` entrypoint.
    ///
    /// # Safety
    ///
    /// It's safe to call this function as long as it's safe to construct, from the given
    /// pointer, byte array of prefix length and `Box<[u8]>` containing the encoded object
    #[doc(hidden)]
    #[cfg(not(test))]
    pub unsafe fn __decode_execute_instruction_context(
        context: *const u8,
    ) -> payloads::Validate<InstructionBox> {
        decode_with_length_prefix_from_raw(context)
    }

    /// Get context for `validate_query()` entrypoint.
    ///
    /// # Safety
    ///
    /// It's safe to call this function as long as it's safe to construct, from the given
    /// pointer, byte array of prefix length and `Box<[u8]>` containing the encoded object
    #[doc(hidden)]
    #[cfg(not(test))]
    pub unsafe fn __decode_validate_query_context(
        context: *const u8,
    ) -> payloads::Validate<AnyQueryBox> {
        decode_with_length_prefix_from_raw(context)
    }

    /// Get context for `migrate()` entrypoint.
    ///
    /// # Safety
    ///
    /// It's safe to call this function as long as it's safe to construct, from the given
    /// pointer, byte array of prefix length and `Box<[u8]>` containing the encoded object
    #[doc(hidden)]
    #[cfg(not(test))]
    pub unsafe fn __decode_migrate_context(context: *const u8) -> payloads::ExecutorContext {
        decode_with_length_prefix_from_raw(context)
    }
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
    unsafe { iroha_smart_contract_utils::encode_and_execute(&data_model, host::set_data_model) }
}

#[cfg(not(test))]
mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
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
        #[cfg(debug_assertions)]
        if !$executor.verdict().is_ok() {
            unreachable!("Executor already denied");
        }

        if let Err(err) = $executor.host().submit($isi) {
            $executor.deny(err);
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
        if $executor.verdict().is_err() {
            unreachable!("Executor already denied");
        }
        $executor.deny($crate::data_model::ValidationFail::NotPermitted(
            ::alloc::fmt::format(::core::format_args!($l)),
        ));
        return;
    }};
    ($executor:ident, $e:expr $(,)?) => {{
        #[cfg(debug_assertions)]
        if $executor.verdict().is_err() {
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
    pub fn build_and_set(self, host: &Iroha) {
        let all_accounts = host.query(FindAccounts::new()).execute().unwrap();
        let all_roles = host.query(FindRoles::new()).execute().unwrap();

        for role in all_roles.into_iter().map(|role| role.unwrap()) {
            for permission in role.permissions() {
                if !self.permissions.contains(permission.name()) {
                    host.submit(&Revoke::role_permission(
                        permission.clone(),
                        role.id().clone(),
                    ))
                    .unwrap();
                }
            }
        }

        for account in all_accounts.into_iter().map(|account| account.unwrap()) {
            let account_permissions = host
                .query(FindPermissionsByAccountId::new(account.id().clone()))
                .execute()
                .unwrap();

            for permission in account_permissions.map(|permission| permission.unwrap()) {
                if !self.permissions.contains(permission.name()) {
                    host.submit(&Revoke::account_permission(
                        permission,
                        account.id().clone(),
                    ))
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
pub trait Execute {
    /// Handle to the host environment.
    fn host(&self) -> &Iroha;

    /// Context of the execution.
    ///
    /// Represents the current state of the world
    fn context(&self) -> &prelude::Context;

    /// Mutable context for e.g. switching to another authority on recursive execution.
    /// Note that mutations are persistent to the instance unless reset
    fn context_mut(&mut self) -> &mut prelude::Context;

    /// Executor verdict.
    fn verdict(&self) -> &Result;

    /// Set executor verdict to deny
    fn deny(&mut self, reason: ValidationFail);
}

pub mod prelude {
    //! Contains useful re-exports

    pub use alloc::vec::Vec;

    pub use iroha_executor_derive::{Entrypoints, Execute, Visit};

    pub use crate::{
        data_model::{
            executor::Result, prelude::*, smart_contract::payloads::ExecutorContext as Context,
            visit::Visit,
        },
        dbg, dbg_panic, deny, execute, DataModelBuilder, DebugExpectExt, DebugUnwrapExt, Execute,
        Iroha,
    };
}
