//! API for *Runtime Executors*.
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;
extern crate self as iroha_executor;

use alloc::vec::Vec;

use data_model::{executor::Result, permission::PermissionTokenId, visit::Visit, ValidationFail};
#[cfg(not(test))]
use data_model::{prelude::*, smart_contract::payloads};
pub use iroha_schema::MetaMap;
pub use iroha_smart_contract as smart_contract;
pub use iroha_smart_contract_utils::{debug, encode_with_length_prefix};
#[cfg(not(test))]
use iroha_smart_contract_utils::{decode_with_length_prefix_from_raw, encode_and_execute};
pub use smart_contract::data_model;

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
pub fn get_validate_instruction_payload() -> payloads::Validate<InstructionExpr> {
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

/// Set new [`PermissionTokenSchema`].
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
pub fn set_permission_token_schema(schema: &data_model::permission::PermissionTokenSchema) {
    // Safety: - ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { encode_and_execute(&schema, host::set_permission_token_schema) }
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

        /// Set new [`PermissionTokenSchema`].
        pub(super) fn set_permission_token_schema(ptr: *const u8, len: usize);
    }
}

/// Shortcut for `return Ok(())`.
#[macro_export]
macro_rules! pass {
    ($executor:ident) => {{
        #[cfg(debug_assertions)]
        if let Err(_error) = $executor.verdict() {
            unreachable!("Executor already denied");
        }

        return;
    }};
}

/// Shortcut for `return Err(ValidationFail)`.
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

/// Macro to parse literal as a type. Panics if failed.
///
/// # Example
///
/// ```no_run
/// use iroha_executor::{data_model::prelude::*, parse};
///
/// let account_id = parse!("alice@wonderland" as AccountId);
/// ```
#[macro_export]
macro_rules! parse {
    ($l:literal as _) => {
        compile_error!(
            "Don't use `_` as a type in this macro, \
                 otherwise panic message would be less informative"
        )
    };
    ($l:literal as $t:ty) => {
        $crate::debug::DebugExpectExt::dbg_expect(
            $l.parse::<$t>(),
            concat!("Failed to parse `", $l, "` as `", stringify!($t), "`"),
        )
    };
}

/// Declare token types of current module. Use it with a full path to the token.
///
/// Used to iterate over token types to validate `Grant` and `Revoke` instructions.
///
///
/// TODO: Replace with procedural macro. Example:
/// ```
/// mod tokens {
///     use std::borrow::ToOwned;
///
///     use iroha_schema::IntoSchema;
///     use iroha_executor_derive::{Token, ValidateGrantRevoke};
///     use serde::{Deserialize, Serialize};
///
///     #[derive(Clone, PartialEq, Deserialize, Serialize, IntoSchema, Token, ValidateGrantRevoke)]
///     #[validate(iroha_executor::permission::OnlyGenesis)]
///     pub struct MyToken;
/// }
/// ```
#[macro_export]
macro_rules! declare_tokens {
    ($($token_ty:ty),+ $(,)?) => {
        macro_rules! map_tokens {
            ($callback:ident) => {$(
                $callback!($token_ty)
            );+}
        }

        pub(crate) use map_tokens;
    }
}

/// Collection of all permission tokens defined by the executor
#[derive(Debug, Clone, Default)]
pub struct PermissionTokenSchema(Vec<PermissionTokenId>, MetaMap);

impl PermissionTokenSchema {
    /// Remove permission token from this collection
    pub fn remove<T: permission::Token>(&mut self) {
        let to_remove = <T as permission::Token>::name();

        if let Some(pos) = self.0.iter().position(|token_id| *token_id == to_remove) {
            self.0.remove(pos);
            <T as iroha_schema::IntoSchema>::remove_from_schema(&mut self.1);
        }
    }

    /// Insert new permission token into this collection
    pub fn insert<T: permission::Token>(&mut self) {
        <T as iroha_schema::IntoSchema>::update_schema_map(&mut self.1);
        self.0.push(<T as permission::Token>::name());
    }

    /// Serializes schema into a JSON string representation
    pub fn serialize(mut self) -> (Vec<PermissionTokenId>, alloc::string::String) {
        self.0.sort();

        (
            self.0,
            serde_json::to_string(&self.1).expect("schema serialization must not fail"),
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
        entrypoint, Constructor, ExpressionEvaluator, Token, Validate, ValidateEntrypoints,
        ValidateGrantRevoke, Visit,
    };
    pub use iroha_smart_contract::{prelude::*, Context};

    pub use super::{
        data_model::{
            executor::{MigrationError, MigrationResult, Result},
            prelude::*,
            visit::Visit,
            ValidationFail,
        },
        declare_tokens, deny, pass, PermissionTokenSchema, Validate,
    };
}
