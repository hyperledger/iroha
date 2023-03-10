//! API for *Runtime Permission Validators*.

#![no_std]

extern crate alloc;

use alloc::string::String;

pub use iroha_validator_derive::entrypoint;
use iroha_wasm::data_model::{permission::validator::Verdict, prelude::*};
pub use iroha_wasm::{self, data_model, ExecuteOnHost};

pub mod prelude {
    //! Contains useful re-exports

    pub use iroha_validator_derive::{entrypoint, Token, Validate};
    pub use iroha_wasm::{
        data_model::{permission::validator::Verdict, prelude::*},
        prelude::*,
        EvaluateOnHost,
    };

    pub use super::traits::{Token, Validate};
    pub use crate::{deny, pass, pass_if, validate_grant_revoke};
}

mod macros {
    //! Contains useful macros

    /// Shortcut for `return Verdict::Pass`.
    #[macro_export]
    macro_rules! pass {
        () => {
            return $crate::iroha_wasm::data_model::permission::validator::Verdict::Pass
        };
    }

    /// Macro to return [`Verdict::Pass`](crate::data_model::permission::validator::Verdict::Pass)
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
                return $crate::iroha_wasm::data_model::permission::validator::Verdict::Pass;
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
            return $crate::iroha_wasm::data_model::permission::validator::Verdict::Deny(
                ::alloc::fmt::format(::core::format_args!($l))
            )
        };
        ($e:expr $(,)?) =>{
            return $crate::iroha_wasm::data_model::permission::validator::Verdict::Deny($e)
        };
        ($fmt:expr, $($arg:tt)*) => {
            return $crate::iroha_wasm::data_model::permission::validator::Verdict::Deny(
                ::alloc::format!($fmt, $($arg)*)
            )
        };
    }

    /// Macro to return [`Verdict::Deny`](crate::data_model::permission::validator::Verdict::Deny)
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

    /// Macro to create [`Grant`](crate::data_model::prelude::Grant) and
    /// [`Revoke`](crate::data_model::prelude::Revoke) instructions validation
    /// for a given token type using its [`Validate`](super::traits::Validate) implementation.
    ///
    /// Generated code will do early return with `instruction` validation verdict
    /// only if it is a `Grant` or `Revoke` instruction.
    ///
    /// Otherwise it will proceed with the rest of the function.
    ///
    /// # Syntax
    ///
    /// ```no_run
    /// validate_grant_revoke!(<Token1, Token2, ...>, (authority_ident, instruction_ident));
    /// ```
    ///
    /// # Example
    ///
    /// ```no_run
    /// #[derive(Token, Validate)]
    /// #[validate(Creator)]
    /// struct CanMintAssetsWithDefinition {
    ///     asset_definition_id: <AssetDefinition as Identifiable>::Id,
    /// }
    ///
    /// #[entrypoint(params = "[authority, instruction]")]
    /// pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    ///    validate_grant_revoke!(<CanMintAssetsWithDefinition>, (authority, instruction));
    ///    // ...
    /// }
    /// ```
    #[macro_export]
    macro_rules! validate_grant_revoke {
        (< $($token:ty),+ $(,)?>, ($authority:ident, $instruction:ident $(,)?)) => {
            match &$instruction {
                $crate::iroha_wasm::data_model::prelude::Instruction::Grant(grant) => {
                    let value = $crate::iroha_wasm::debug::DebugExpectExt::dbg_expect(<
                        $crate::iroha_wasm::data_model::prelude::EvaluatesTo<$crate::iroha_wasm::data_model::prelude::Value>
                        as
                        $crate::iroha_wasm::EvaluateOnHost
                    >::evaluate(grant.object()),
                        "Failed to evaluate `Grant` object"
                    );

                    if let $crate::iroha_wasm::data_model::prelude::Value::PermissionToken(permission_token) = value {$(
                        if let Ok(concrete_token) =
                            <$token as ::core::convert::TryFrom<_>>::try_from(
                                <
                                    $crate::iroha_wasm::data_model::permission::token::Token as ::core::clone::Clone
                                >::clone(&permission_token)
                            )
                        {
                            return <$token as ::iroha_validator::traits::Validate>::validate_grant(
                                &concrete_token,
                                &$authority
                            );
                        }
                    )+}
                }
                $crate::iroha_wasm::data_model::prelude::Instruction::Revoke(revoke) => {
                    let value = $crate::iroha_wasm::debug::DebugExpectExt::dbg_expect(<
                        $crate::iroha_wasm::data_model::prelude::EvaluatesTo<$crate::iroha_wasm::data_model::prelude::Value>
                        as
                        $crate::iroha_wasm::EvaluateOnHost
                    >::evaluate(revoke.object()),
                        "Failed to evaluate `Revoke` object"
                    );

                    if let $crate::iroha_wasm::data_model::prelude::Value::PermissionToken(permission_token) = value {$(
                        if let Ok(concrete_token) =
                            <$token as ::core::convert::TryFrom<_>>::try_from(
                                <
                                    $crate::iroha_wasm::data_model::permission::token::Token as ::core::clone::Clone
                                >::clone(&permission_token)
                            )
                        {
                            return <$token as ::iroha_validator::traits::Validate>::validate_revoke(
                                &concrete_token,
                                &$authority
                            );
                        }
                    )+}
                }
                _ => {}
            }
        };
    }

    #[cfg(test)]
    mod tests {
        //! Tests in this modules can't be doc-tests because of `compile_error!` on native target
        //! and `webassembly-test-runner` on wasm target.

        use webassembly_test::webassembly_test;

        use crate::{
            alloc::borrow::ToOwned as _, data_model::permission::validator::Verdict, deny,
        };

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
}

/// Error type for `TryFrom<PermissionToken>` implementations.
#[derive(Debug, Clone)]
pub enum PermissionTokenConversionError {
    /// Unexpected token id.
    Id(PermissionTokenId),
    /// Missing parameter.
    Param(&'static str),
    // TODO: Improve this error
    /// Unexpected parameter value.
    Value(String),
}

pub mod traits {
    //! Contains traits related to validators

    use super::*;

    /// [`Token`] trait is used to check if the token is owned by the account.
    pub trait Token:
        TryFrom<PermissionToken, Error = PermissionTokenConversionError> + Validate
    {
        /// Get definition id of this token
        fn definition_id() -> PermissionTokenId;

        /// Check if token is owned by the account using evaluation on host.
        ///
        /// Basically it's a wrapper around [`DoesAccountHavePermissionToken`] query.
        fn is_owned_by(&self, account_id: &<Account as Identifiable>::Id) -> bool;
    }

    /// Trait that should be implemented for all permission tokens.
    /// Provides a function to check validity of [`Grant`] and [`Revoke`]
    /// instructions containing implementing token.
    pub trait Validate {
        /// Validate [`Grant`] instruction for this token.
        fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Verdict;

        /// Validate [`Revoke`] instruction for this token.
        fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Verdict;
    }
}

pub mod pass_conditions {
    //! Contains some common pass conditions used in [`Validate`](crate::data_model::validator::prelude::Validate)

    use super::*;

    /// Predicate-like trait used for pass conditions to identify if [`Grant`] or [`Revoke`] should be allowed.
    pub trait PassCondition {
        fn validate(&self, authority: &<Account as Identifiable>::Id) -> Verdict;
    }

    pub mod derive_conversions {
        //! Module with derive macros to generate conversion from custom strongly-typed token
        //! to some pass condition to successfully derive [`Validate`](iroha_validator_derive::Validate)

        pub mod asset {
            //! Module with derives related to asset tokens

            pub use iroha_validator_derive::RefIntoAssetOwner as Owner;
        }

        pub mod asset_definition {
            //! Module with derives related to asset definition tokens

            pub use iroha_validator_derive::RefIntoAssetDefinitionOwner as Owner;
        }

        pub mod account {
            //! Module with derives related to account tokens

            pub use iroha_validator_derive::RefIntoAccountOwner as Owner;
        }
    }

    pub mod asset {
        //! Module with pass conditions for assets-related to tokens

        use super::*;

        /// Pass condition that checks if `authority` is the owner of `asset_id`.
        #[derive(Debug, Clone)]
        pub struct Owner<'asset> {
            pub asset_id: &'asset <Asset as Identifiable>::Id,
        }

        impl PassCondition for Owner<'_> {
            fn validate(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
                pass_if!(self.asset_id.account_id() == authority);
                deny!("Can't give permission to access asset owned by another account")
            }
        }
    }

    pub mod asset_definition {
        //! Module with pass conditions for asset definitions related to tokens

        use super::*;

        /// Pass condition that checks if `authority` is the owner of `asset_definition_id`.
        #[derive(Debug, Clone)]
        pub struct Owner<'asset_definition> {
            pub asset_definition_id: &'asset_definition <AssetDefinition as Identifiable>::Id,
        }

        impl PassCondition for Owner<'_> {
            fn validate(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
                pass_if!(utils::is_asset_definition_owner(
                    self.asset_definition_id,
                    authority
                ));
                deny!("Can't give permission to access asset definition owned by another account")
            }
        }
    }

    pub mod account {
        //! Module with pass conditions for assets-related to tokens

        use super::*;

        /// Pass condition that checks if `authority` is the owner of `account_id`.
        #[derive(Debug, Clone)]
        pub struct Owner<'asset> {
            pub account_id: &'asset <Account as Identifiable>::Id,
        }

        impl PassCondition for Owner<'_> {
            fn validate(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
                pass_if!(self.account_id == authority);
                deny!("Can't give permission to access another account")
            }
        }
    }

    /// Pass condition that always passes.
    #[derive(Debug, Default, Copy, Clone)]
    pub struct AlwaysPass;

    impl PassCondition for AlwaysPass {
        fn validate(&self, _: &<Account as Identifiable>::Id) -> Verdict {
            pass!()
        }
    }

    impl<T: traits::Token> From<&T> for AlwaysPass {
        fn from(_: &T) -> Self {
            Self::default()
        }
    }

    /// Pass condition that allows operation only in genesis.
    ///
    /// In other words it always denies the operation, because runtime validators are not used
    /// in genesis validation.
    #[derive(Debug, Default, Copy, Clone)]
    pub struct OnlyGenesis;

    impl PassCondition for OnlyGenesis {
        fn validate(&self, _: &<Account as Identifiable>::Id) -> Verdict {
            deny!("This operation is always denied and only allowed inside the genesis block")
        }
    }

    impl<T: traits::Token> From<&T> for OnlyGenesis {
        fn from(_: &T) -> Self {
            Self::default()
        }
    }
}

pub mod utils {
    //! Contains some utils for validators

    use super::*;

    /// Check if `authority` is the owner of `asset_definition_id`.
    ///
    /// Wrapper around [`IsAssetDefinitionOwner`](crate::data_model::prelude::IsAssetDefinitionOwner) query.
    pub fn is_asset_definition_owner(
        asset_definition_id: &<AssetDefinition as Identifiable>::Id,
        authority: &<Account as Identifiable>::Id,
    ) -> bool {
        use iroha_wasm::{debug::DebugExpectExt as _, ExecuteOnHost as _};

        QueryBox::from(IsAssetDefinitionOwner::new(
            asset_definition_id.clone(),
            authority.clone(),
        ))
        .execute()
        .try_into()
        .dbg_expect("Failed to convert `IsAssetDefinitionOwner` query result into `bool`")
    }
}
