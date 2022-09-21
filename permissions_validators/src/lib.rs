//! Out of box implementations for common permission checks.
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::collections::BTreeMap;

use derive_more::Display;
use iroha_core::{
    prelude::*,
    smartcontracts::{
        permissions::{
            judge::{InstructionJudgeBoxed, QueryJudgeBoxed},
            HasToken, PermissionTokenTrait as _,
            ValidatorVerdict::*,
        },
        Evaluate,
    },
};
use iroha_data_model::{isi::*, prelude::*};
use serde::Serialize;

macro_rules! try_evaluate_or_deny {
    ($e:expr, $wsv:ident) => {
        match $e.evaluate($wsv, &Context::new()) {
            Ok(value) => value,
            Err(err) => return ValidatorVerdict::Deny(err.to_string()),
        }
    };
}

// TODO: Use [`FromResidual`](https://doc.rust-lang.org/std/ops/trait.FromResidual.html)
// once it becomes stable
macro_rules! ok_or_deny {
    ($r:expr) => {
        match $r {
            Ok(value) => value,
            Err(err) => return ValidatorVerdict::Deny(err),
        }
    };
}

// TODO: Use [`FromResidual`](https://doc.rust-lang.org/std/ops/trait.FromResidual.html)
// once it becomes stable
macro_rules! ok_or_skip {
    ($r:expr) => {
        match $r {
            Ok(value) => value,
            Err(_) => return ValidatorVerdict::Skip,
        }
    };
}

macro_rules! declare_token {
    (
        $(#[$outer_meta:meta])* // Structure attributes
        $ident:ident {          // Structure definition
            $(
                $(#[$inner_meta:meta])* // Field attributes
                $param_name:ident ($param_string:literal): $param_typ:ty
             ),* $(,)? // allow trailing comma
        },
        $string:tt // Token id
    ) => {

        // For tokens with no parameters
        #[allow(missing_copy_implementations)]
        $(#[$outer_meta])*
        ///
        /// A wrapper around [PermissionToken](iroha_data_model::permission::Token).
        #[derive(
            Clone,
            Debug,
            parity_scale_codec::Encode,
            parity_scale_codec::Decode,
            serde::Serialize,
            serde::Deserialize,
            iroha_schema::IntoSchema,
        )]
        pub struct $ident
        where $($param_typ: Into<Value> + ::iroha_data_model::permission::token::ValueTrait,)* {
            $(
                $(#[$inner_meta])*
                #[doc = concat!(
                    "\nCorresponding parameter name in generic `[PermissionToken]` is `\"",
                    $param_string,
                    "\"`.",
                )]
                pub $param_name : $param_typ
             ),*
        }

        impl $ident {
            $(
              #[doc = concat!("Get `", stringify!($param_name), "` parameter name")]
              pub fn $param_name() -> &'static Name {
                static NAME: once_cell::sync::Lazy<Name> =
                    once_cell::sync::Lazy::new(|| $param_string.parse().expect("Tested. Works."));
                &NAME
              }
            )*

            /// Constructor
            #[inline]
            #[allow(clippy::new_without_default)] // For tokens with no parameters
            pub fn new($($param_name: $param_typ),*) -> Self {
                Self {
                    $($param_name,)*
                }
            }
        }

        impl iroha_core::smartcontracts::isi::permissions::PermissionTokenTrait for $ident {
            /// Get associated [`PermissionTokenDefinition`].
            fn definition() -> &'static PermissionTokenDefinition {
                static DEFINITION: once_cell::sync::Lazy<PermissionTokenDefinition> =
                    once_cell::sync::Lazy::new(|| {
                        PermissionTokenDefinition::new(
                            $string.parse().expect("Failed to parse permission token definition id: \
                                                    `{$string}`. This is a bug")
                        )
                        .with_params([
                            $((
                                $param_string.parse()
                                    .expect("Failed to parse permission token parameter name: \
                                             `{$param_string}`. This is a bug"),
                                <$param_typ as ::iroha_data_model::permission::token::ValueTrait>::TYPE
                            ),)*
                        ])
                    });
                &DEFINITION
            }
        }

        impl From<$ident> for iroha_data_model::permission::Token {
            #[allow(unused)] // `value` can be unused if token has no params
            fn from(value: $ident) -> Self {
                iroha_data_model::permission::Token::new(
                    <
                        $ident as
                        iroha_core::smartcontracts::isi::permissions::PermissionTokenTrait
                    >::definition_id().clone()
                )
                .with_params([
                    $(($ident::$param_name().clone(), value.$param_name.into())),*
                ])
            }
        }

        impl TryFrom<iroha_data_model::permission::Token> for $ident {
            type Error = iroha_core::smartcontracts::isi::permissions::PredefinedTokenConversionError;

            #[allow(unused)] // `params` can be unused if token has none
            fn try_from(
                token: iroha_data_model::permission::Token
            ) -> core::result::Result<Self, Self::Error> {
                if token.definition_id() != <
                        Self as
                        iroha_core::smartcontracts::isi::permissions::PermissionTokenTrait
                        >::definition_id() {
                    return Err(Self::Error::Id(token.definition_id().clone()))
                }
                let mut params = token.params().collect::<std::collections::HashMap<_, _>>();
                Ok(Self::new($(
                  <$param_typ>::try_from(
                    params
                     .remove(Self::$param_name())
                     .cloned()
                     .ok_or(Self::Error::Param(Self::$param_name()))?
                  )
                  .map_err(|_| Self::Error::Value(Self::$param_name()),)?
                ),*))
            }
        }
    };
}

// I need to put these modules after the macro definitions.
pub mod private_blockchain;
pub mod public_blockchain;
