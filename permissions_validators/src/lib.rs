//! Out of box implementations for common permission checks.

use std::collections::BTreeMap;

use iroha_core::{
    prelude::*,
    smartcontracts::{
        permissions::{
            prelude::*, HasToken, IsAllowed, IsInstructionAllowedBoxed, IsQueryAllowedBoxed,
            ValidatorApplyOr, ValidatorBuilder,
        },
        Evaluate,
    },
    wsv::WorldTrait,
};
use iroha_data_model::{isi::*, prelude::*};
use iroha_macro::error::ErrorTryFromEnum;
use once_cell::sync::Lazy;

macro_rules! impl_from_item_for_instruction_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for IsInstructionAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_query_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for IsQueryAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_granted_token_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for HasTokenBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl<W: WorldTrait> From<$ty> for IsInstructionAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                let validator: HasTokenBoxed<W> = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_grant_instruction_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for IsGrantAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl<W: WorldTrait> From<$ty> for IsInstructionAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                let validator: IsGrantAllowedBoxed<W> = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! impl_from_item_for_revoke_instruction_validator_box {
    ( $ty:ty ) => {
        impl<W: WorldTrait> From<$ty> for IsRevokeAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                Box::new(validator)
            }
        }

        impl<W: WorldTrait> From<$ty> for IsInstructionAllowedBoxed<W> {
            fn from(validator: $ty) -> Self {
                let validator: IsRevokeAllowedBoxed<W> = validator.into();
                Box::new(validator)
            }
        }
    };
}

macro_rules! try_into_or_exit {
    ( $ident:ident ) => {
        if let Ok(into) = $ident.try_into() {
            into
        } else {
            return Ok(());
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
                static  NAME: once_cell::sync::Lazy<Name> =
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
            pub fn new($($param_name: $param_typ),*) -> Self {
                Self {
                    $($param_name,)*
                }
            }
        }

        impl From<$ident> for iroha_data_model::permissions::PermissionToken {
            fn from(value: $ident) -> Self {
                iroha_data_model::permissions::PermissionToken::new($ident::name().clone())
                    .with_params([
                      $(($ident::$param_name().clone(), value.$param_name.into())),*
                    ])
            }
        }

        impl TryFrom<iroha_data_model::permissions::PermissionToken> for $ident {
            type Error = PredefinedTokenConversionError;

            fn try_from(
                token: iroha_data_model::permissions::PermissionToken
            ) -> Result<Self, Self::Error> {
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
