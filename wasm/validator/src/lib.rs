//! API for *Runtime Validators*.
#![no_std]

extern crate alloc;
// NOTE: Enables us to implement derive macros
// that refer to the this crate for this crate
#[cfg(feature = "default-validator")]
extern crate self as iroha_validator;

#[cfg(feature = "default-validator")]
pub use default::DefaultValidator;
use iroha_wasm::data_model::{validator::Result, visit::Visit, ValidationFail};
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
/// Supports [`format!`](alloc::format) syntax as well as any expression returning [`String`](alloc::string::String).
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

/// Validator of Iroha operations
pub trait Validate: Visit {
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
        data_model::{prelude::*, validator::Result, visit::Visit, ValidationFail},
        prelude::*,
        Context,
    };

    #[cfg(feature = "default-validator")]
    pub use super::DefaultValidator;
    pub use super::{declare_tokens, deny, pass, Validate};
}
