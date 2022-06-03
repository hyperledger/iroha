//! Out of box implementations for common permission checks.

use std::collections::BTreeMap;

use iroha_core::{
    prelude::*,
    smartcontracts::{
        permissions::{
            judge::{InstructionJudgeBoxed, QueryJudgeBoxed},
            HasToken,
            ValidatorVerdict::*,
        },
        Evaluate,
    },
};
use iroha_data_model::{isi::*, prelude::*};
use iroha_macro::error::ErrorTryFromEnum;
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
        $ident:ident {          // Structure definiton
            $(
                $(#[$inner_meta:meta])* // Field attributes
                $param_name:ident ($param_string:literal): $param_typ:ty
             ),* $(,)? // allow trailing comma
        },
        $string:tt // Token name
    ) => {

        // For tokens with no parameters
        #[allow(missing_copy_implementations)]
        $(#[$outer_meta])*
        ///
        /// A wrapper around [PermissionToken](iroha_data_model::permissions::PermissionToken).
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
        where $($param_typ: Into<Value>,)* {
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
            /// Get associated [`PermissionToken`](iroha_data_model::permissions::PermissionToken) name.
            pub fn name() -> &'static Name {
                static NAME: once_cell::sync::Lazy<Name> =
                    once_cell::sync::Lazy::new(|| $string.parse().expect("Tested. Works."));
                &NAME
            }

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

        impl From<$ident> for iroha_data_model::permissions::PermissionToken {
            #[allow(unused)] // `value` can be unused if token has no params
            fn from(value: $ident) -> Self {
                iroha_data_model::permissions::PermissionToken::new($ident::name().clone())
                    .with_params([
                      $(($ident::$param_name().clone(), value.$param_name.into())),*
                    ])
            }
        }

        impl TryFrom<iroha_data_model::permissions::PermissionToken> for $ident {
            type Error = PredefinedTokenConversionError;

            #[allow(unused)] // `params` can be unused if token has none
            fn try_from(
                token: iroha_data_model::permissions::PermissionToken
            ) -> std::result::Result<Self, Self::Error> {
                if token.name() != Self::name() {
                    return Err(Self::Error::Name(token.name().clone()))
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

/// Represents error when converting specialized permission tokens
/// to generic `[PermissionToken]`
#[derive(Debug, thiserror::Error)]
pub enum PredefinedTokenConversionError {
    /// Wrong token name
    #[error("Wrong token name: {0}")]
    Name(Name),
    /// Parameter not present in token parameters
    #[error("Parameter {0} not found")]
    Param(&'static Name),
    /// Unexpected value for parameter
    #[error("Wrong value for parameter {0}")]
    Value(&'static Name),
}

// I need to put these modules after the macro definitions.
pub mod private_blockchain;
pub mod public_blockchain;
