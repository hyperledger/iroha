//! API for *Runtime Validators*.

#![no_std]

extern crate alloc;
// NOTE: Enables us to implement derive macros
// that refer to the this crate for this crate
#[cfg(feature = "default-validator")]
extern crate self as iroha_validator;

#[cfg(feature = "default-validator")]
pub use default::DefaultValidator;
pub use iroha_wasm::{self, data_model, ExecuteOnHost};
pub use visitor::Validate;

#[cfg(feature = "default-validator")]
pub mod default;
pub mod permission;
pub mod visitor;

/// Shortcut for `return Verdict::Pass`.
#[macro_export]
macro_rules! pass {
    () => {
        return $crate::iroha_wasm::data_model::validator::Verdict::Pass
    };
}

/// Macro to return [`Verdict::Pass`](crate::data_model::validator::Verdict::Pass)
/// if the expression is `true`.
///
/// # Example
///
/// ```no_run
/// pass_if!(asset_id.account_id() == authority);
/// ```
#[macro_export]
macro_rules! pass_if {
    ($e:expr) => {
        if $e {
            return $crate::iroha_wasm::data_model::validator::Verdict::Pass;
        }
    };
}

/// Shortcut for `return Verdict::Deny(...)`.
///
/// Supports [`format!`](alloc::format) syntax as well as any expression returning [`String`](alloc::string::String).
///
/// # Example
///
/// ```no_run
/// deny!("Some reason");
/// deny!("Reason: {}", reason);
/// deny!("Reason: {reason}");
/// deny!(get_reason());
/// ```
#[macro_export]
macro_rules! deny {
        ($l:literal $(,)?) => {
            return $crate::iroha_wasm::data_model::validator::Verdict::Deny(
                ::alloc::fmt::format(::core::format_args!($l))
            )
        };
        ($e:expr $(,)?) =>{
            return $crate::iroha_wasm::data_model::validator::Verdict::Deny($e)
        };
        ($fmt:expr, $($arg:tt)*) => {
            return $crate::iroha_wasm::data_model::validator::Verdict::Deny(
                ::alloc::format!($fmt, $($arg)*)
            )
        };
    }

/// Macro to return [`Verdict::Deny`](crate::data_model::validator::Verdict::Deny)
/// if the expression is `true`.
///
/// # Example
///
/// ```no_run
/// deny_if!(asset_id.account_id() != authority, "You have to be an asset owner");
/// deny_if!(asset_id.account_id() != authority, "You have to be an {} owner", asset_id);
/// deny_if!(asset_id.account_id() != authority, construct_reason(&asset_id));
/// ```
#[macro_export]
macro_rules! deny_if {
        ($e:expr, $l:literal $(,)?) => {
            if $e {
                deny!($l);
            }
        };
        ($e:expr, $r:expr $(,)?) =>{
            if $e {
                deny!($r);
            }
        };
        ($e:expr, $fmt:expr, $($arg:tt)*) => {
            if $e {
                deny!($fmt, $($arg)*);
            }
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
/// let account_id = parse!("alice@wonderland" as <Account as Identifiable>::Id);
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

pub mod prelude {
    //! Contains useful re-exports

    pub use iroha_validator_derive::{entrypoint, Token, ValidateGrantRevoke};
    pub use iroha_wasm::{
        data_model::{prelude::*, validator::Verdict},
        prelude::*,
        Context,
    };

    #[cfg(feature = "default-validator")]
    pub use super::DefaultValidator;
    pub use crate::{declare_tokens, deny, pass, pass_if, visitor::Validate};
}

#[cfg(test)]
mod tests {
    //! Tests in this modules can't be doc-tests because of `compile_error!` on native target
    //! and `webassembly-test-runner` on wasm target.

    use webassembly_test::webassembly_test;

    use crate::{alloc::borrow::ToOwned as _, data_model::validator::Verdict, deny};

    #[webassembly_test]
    fn test_deny() {
        let a = || deny!("Some reason");
        assert_eq!(a(), Verdict::Deny("Some reason".to_owned()));

        let get_reason = || "Reason from expression".to_owned();
        let b = || deny!(get_reason());
        assert_eq!(b(), Verdict::Deny("Reason from expression".to_owned()));

        let mes = "Format message";
        let c = || deny!("Reason: {}", mes);
        assert_eq!(c(), Verdict::Deny("Reason: Format message".to_owned()));

        let mes = "Advanced format message";
        let d = || deny!("Reason: {mes}");
        assert_eq!(
            d(),
            Verdict::Deny("Reason: Advanced format message".to_owned())
        );
    }

    #[webassembly_test]
    fn test_deny_if() {
        let a = || {
            deny_if!(true, "Some reason");
            unreachable!()
        };
        assert_eq!(a(), Verdict::Deny("Some reason".to_owned()));

        let get_reason = || "Reason from expression".to_owned();
        let b = || {
            deny_if!(true, get_reason());
            unreachable!()
        };
        assert_eq!(b(), Verdict::Deny("Reason from expression".to_owned()));

        let mes = "Format message";
        let c = || {
            deny_if!(true, "Reason: {}", mes);
            unreachable!()
        };
        assert_eq!(c(), Verdict::Deny("Reason: Format message".to_owned()));

        let mes = "Advanced format message";
        let d = || {
            deny_if!(true, "Reason: {mes}");
            unreachable!()
        };
        assert_eq!(
            d(),
            Verdict::Deny("Reason: Advanced format message".to_owned())
        );
    }
}
