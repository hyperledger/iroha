//! API for *Runtime Validators*.
#![no_std]

extern crate alloc;
// NOTE: Enables us to implement derive macros
// that refer to the this crate for this crate
#[cfg(feature = "default-validator")]
extern crate self as iroha_validator;

use alloc::vec::Vec;

#[cfg(feature = "default-validator")]
pub use default::DefaultValidator;
pub use iroha_schema::MetaMap;
use iroha_wasm::data_model::{
    permission::PermissionTokenId,
    validator::{MigrationResult, Result},
    visit::Visit,
    ValidationFail,
};
pub use iroha_wasm::{self, data_model};

#[cfg(feature = "default-validator")]
pub mod default;
pub mod permission;

/// Shortcut for `return Ok(())`.
#[macro_export]
macro_rules! pass {
    ($validator:ident) => {{
        #[cfg(debug_assertions)]
        if let Err(_error) = $validator.verdict() {
            unreachable!("Validator already denied");
        }

        return;
    }};
}

/// Shortcut for `return Err(ValidationFail)`.
///
/// Supports [`format!`](alloc::fmt::format) syntax as well as any expression returning [`String`](alloc::string::String).
#[macro_export]
macro_rules! deny {
    ($validator:ident, $l:literal $(,)?) => {{
        #[cfg(debug_assertions)]
        if let Err(_error) = $validator.verdict() {
            unreachable!("Validator already denied");
        }
        $validator.deny(::iroha_validator::data_model::ValidationFail::NotPermitted(
            ::alloc::fmt::format(::core::format_args!($l)),
        ));
        return;
    }};
    ($validator:ident, $e:expr $(,)?) => {{
        #[cfg(debug_assertions)]
        if let Err(_error) = $validator.verdict() {
            unreachable!("Validator already denied");
        }
        $validator.deny($e);
        return;
    }};
}

/// Macro to parse literal as a type. Panics if failed.
///
/// # Example
///
/// ```no_run
/// use iroha_wasm::parse;
/// use data_model::prelude::*;
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
        $crate::iroha_wasm::debug::DebugExpectExt::dbg_expect(
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
/// #[tokens(path = "crate::current_module")]
/// mod tokens {
///     #[derive(Token, ...)]
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

/// Collection of all permission tokens defined by the validator
#[derive(Debug, Clone, Default)]
pub struct PermissionTokenSchema(Vec<PermissionTokenId>, MetaMap);

impl PermissionTokenSchema {
    /// Remove permission token from this collection
    pub fn remove<T: iroha_schema::IntoSchema>(&mut self) {
        let to_remove = ::iroha_validator::iroha_wasm::debug::DebugExpectExt::dbg_expect(
            <T as iroha_schema::IntoSchema>::type_name().parse(),
            "Failed to parse permission token as `Name`",
        );

        if let Some(pos) = self.0.iter().position(|token_id| *token_id == to_remove) {
            self.0.remove(pos);
            <T as iroha_schema::IntoSchema>::remove_from_schema(&mut self.1);
        }
    }

    /// Insert new permission token into this collection
    pub fn insert<T: iroha_schema::IntoSchema>(&mut self) {
        <T as iroha_schema::IntoSchema>::update_schema_map(&mut self.1);

        self.0.push(
            ::iroha_validator::iroha_wasm::debug::DebugExpectExt::dbg_expect(
                <T as iroha_schema::IntoSchema>::type_name().parse(),
                "Failed to parse permission token as `Name`",
            ),
        );
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

/// Validator of Iroha operations
pub trait Validate: Visit {
    /// Migrate previous validator to the current version.
    ///
    /// This function should be called by `migrate` entrypoint,
    /// which will be called by Iroha only once just before upgrading validator.
    ///
    /// # Errors
    ///
    /// Concrete errors are specific to the implementation.
    ///
    /// If `migrate()` entrypoint fails then the whole `Upgrade` instruction
    /// will be denied and previous validator will stay unchanged.
    fn migrate() -> MigrationResult;

    /// Validator verdict.
    fn verdict(&self) -> &Result;

    /// Set validator verdict to deny
    fn deny(&mut self, reason: ValidationFail);
}

pub mod prelude {
    //! Contains useful re-exports

    pub use alloc::vec::Vec;

    pub use iroha_validator_derive::{entrypoint, Token, ValidateGrantRevoke};
    pub use iroha_wasm::{
        data_model::{
            prelude::*,
            validator::{MigrationError, MigrationResult, Result},
            visit::Visit,
            ValidationFail,
        },
        prelude::*,
        Context,
    };

    #[cfg(feature = "default-validator")]
    pub use super::DefaultValidator;
    pub use super::{declare_tokens, deny, pass, PermissionTokenSchema, Validate};
}
