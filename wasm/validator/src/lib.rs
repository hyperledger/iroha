//! API for *Runtime Validators*.
#![no_std]

extern crate alloc;
extern crate self as iroha_validator;

use alloc::vec::Vec;

pub use iroha_schema::MetaMap;
pub use iroha_wasm::{self, data_model};
use prelude::*;

pub mod default;
pub mod permission;

#[macro_export]
#[doc(hidden)]
macro_rules! pass {
    ($validator:ident, $verdict_fn:ident, $passing_object:literal) => {{
        #[cfg(debug_assertions)]
        if let $crate::MaybeVerdict::Verdict(Err(_error)) = $validator.$verdict_fn() {
            unreachable!(concat!("Validator already denied ", $passing_object));
        }

        return;
    }};
}

/// Shortcut check if validator transaction verdict is `Err` (on `#[cfg(debug_assertions)]` only)
/// and return from function.
#[macro_export]
macro_rules! pass_transaction {
    ($validator:ident) => {
        $crate::pass!($validator, transaction_verdict, "transaction")
    };
}

/// Shortcut check if validator instruction verdict is `Err` (on `#[cfg(debug_assertions)]` only)
/// and return from function.
#[macro_export]
macro_rules! pass_instruction {
    ($validator:ident) => {
        $crate::pass!($validator, instruction_verdict, "instruction")
    };
}

/// Shortcut check if validator query verdict is `Err` (on `#[cfg(debug_assertions)]` only)
/// and return from function.
#[macro_export]
macro_rules! pass_query {
    ($validator:ident) => {
        $crate::pass!($validator, query_verdict, "query")
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! deny {
    ($validator:ident, $verdict_fn:ident, $set_verdict_fn:ident, $denying_object:literal, $fmt:literal $(,$($args:tt)*)?) => {{
        $crate::deny!(@check_already_denied $validator, $verdict_fn, $denying_object);

        $validator.$set_verdict_fn(Err(::iroha_validator::data_model::ValidationFail::NotPermitted(
            ::alloc::fmt::format(::core::format_args!($fmt $(, $($args)*)?)),
        )));
        return;
    }};
    ($validator:ident, $verdict_fn:ident, $set_verdict_fn:ident, $denying_object:literal, $e:expr) => {{
        $crate::deny!(@check_already_denied $validator, $verdict_fn, $denying_object);

        $validator.$set_verdict_fn(Err($e));
        return;
    }};
    (@check_already_denied $validator:ident, $verdict_fn:ident, $denying_object:literal) => {
        #[cfg(debug_assertions)]
        if let $crate::MaybeVerdict::Verdict(Err(_error)) =
            $validator.$verdict_fn()
        {
            unreachable!(concat!("Validator already denied ", $denying_object));
        }
    }
}

/// Shortcut to set `Err(ValidationFail)` to transaction verdict and return from function.
///
/// Supports [`format!`](alloc::fmt::format) syntax as well as any expression returning [`String`](alloc::string::String).
#[macro_export]
macro_rules! deny_transaction {
    ($validator:ident, $fmt:literal $(,$($args:tt)*)?) => {
        $crate::deny!($validator, transaction_verdict, set_transaction_verdict, "transaction", $fmt $(, $($args)*)?)
    };
    ($validator:ident, $e:expr $(,)?) => {
        $crate::deny!($validator, transaction_verdict, set_transaction_verdict, "transaction", $e)
    };
}

/// Shortcut to set `Err(ValidationFail)` to instruction verdict and return from function.
///
/// Supports [`format!`](alloc::fmt::format) syntax as well as any expression returning [`String`](alloc::string::String).
#[macro_export]
macro_rules! deny_instruction {
    ($validator:ident, $fmt:literal $(,$($args:tt)*)?) => {
        $crate::deny!($validator, instruction_verdict, set_instruction_verdict, "instruction", $fmt $(, $($args)*)?)
    };
    ($validator:ident, $e:expr $(,)?) => {
        $crate::deny!($validator, instruction_verdict, set_instruction_verdict, "instruction", $e)
    };
}

/// Shortcut to set `Err(ValidationFail)` to query verdict and return from function.
///
/// Supports [`format!`](alloc::fmt::format) syntax as well as any expression returning [`String`](alloc::string::String).
#[macro_export]
macro_rules! deny_query {
    ($validator:ident, $fmt:literal $(,$($args:tt)*)?) => {
        $crate::deny!($validator, query_verdict, set_query_verdict, "query", $fmt $(, $($args)*)?)
    };
    ($validator:ident, $e:expr $(,)?) => {
        $crate::deny!($validator, query_verdict, set_query_verdict, "query", $e)
    };
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

/// Technically the same as `Option<Result<T, E>>` but with another semantic.
#[derive(Debug, Default, Clone)]
pub enum MaybeVerdict<T, E = ValidationFail> {
    #[default]
    Uninitialized,
    Verdict(Result<T, E>),
}

impl<T, E> MaybeVerdict<T, E> {
    /// Cast [`MaybeVerdict`] reference to a [`MaybeVerdict`] with reference.
    pub const fn as_ref(&self) -> MaybeVerdict<&T, &E> {
        match self {
            Self::Uninitialized => MaybeVerdict::Uninitialized,
            Self::Verdict(ref value) => MaybeVerdict::Verdict(value.as_ref()),
        }
    }

    /// Map value if initialized, otherwise return `default`.
    pub fn map_or<F, U>(self, default: U, f: F) -> U
    where
        F: FnOnce(Result<T, E>) -> U,
    {
        match self {
            Self::Uninitialized => default,
            Self::Verdict(value) => f(value),
        }
    }

    /// Unwrap the value assuming it is initialized with verdict.
    ///
    /// # Panics
    ///
    /// Panics if value is [`Uninitialized`](Self::Uninitialized).
    #[allow(clippy::missing_errors_doc)]
    pub fn assume_verdict(self) -> Result<T, E> {
        match self {
            Self::Uninitialized => {
                crate::dbg_panic("`assume_verdict()` called on `Uninitialized` value")
            }
            Self::Verdict(value) => value,
        }
    }

    /// Check if value is:
    ///
    /// - [`Verdict`](Self::Verdict) with [`Ok`] or
    /// - [`Uninitialized`](Self::Uninitialized).
    pub fn is_ok_or_uninitialized(&self) -> bool {
        self.as_ref().map_or(true, |verdict| verdict.is_ok())
    }
}

/// Collection of all permission tokens defined by the validator
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

/// Validator of Iroha operations.
pub trait Validate: Visit {
    /// Current block height.
    fn block_height(&self) -> u64;

    /// Current validator transaction verdict.
    fn transaction_verdict(&self) -> MaybeVerdict<&TransactionValidationOutput, &ValidationFail>;

    /// Set validator transaction verdict.
    fn set_transaction_verdict(&mut self, verdict: Result<TransactionValidationOutput>);

    /// Current validator instruction verdict.
    fn instruction_verdict(&self) -> MaybeVerdict<&InstructionValidationOutput, &ValidationFail>;

    /// Set validator instruction verdict.
    fn set_instruction_verdict(&mut self, verdict: Result<InstructionValidationOutput>);

    /// Current validator query verdict.
    fn query_verdict(&self) -> MaybeVerdict<&QueryValidationOutput, &ValidationFail>;

    /// Set validator query verdict.
    fn set_query_verdict(&mut self, verdict: Result<QueryValidationOutput>);
}

pub mod prelude {
    //! Contains useful re-exports

    pub use alloc::vec::Vec;

    pub use iroha_validator_derive::{entrypoint, Token, ValidateGrantRevoke};
    pub use iroha_wasm::{
        data_model::{
            prelude::*,
            validator::{
                InstructionValidationOutput, MigrationError, MigrationResult,
                QueryValidationOutput, Result, TransactionValidationOutput,
            },
            visit::Visit,
            ValidationFail,
        },
        prelude::*,
        Context,
    };

    pub use super::{
        declare_tokens, deny_instruction, deny_query, deny_transaction, pass_instruction,
        pass_query, pass_transaction, MaybeVerdict, PermissionTokenSchema, Validate,
    };
}
