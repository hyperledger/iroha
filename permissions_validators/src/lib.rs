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
                $param_name:ident ($param_string:literal): $param_typ:ty
             ),* $(,)? // allow trailing comma
        },
        $string:tt // Token name
    ) => {

        $(#[$outer_meta])*
        ///
        /// A wrapper around [PermissionToken](iroha_data_model::permissions::PermissionToken).
        #[derive(iroha_schema::IntoSchema)]
        pub struct $ident
        where $($param_typ: Into<Value>,)* {
            $(
                $param_name : $param_typ
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
    };
}

// I need to put these modules after the macro definitions.
pub mod private_blockchain;
pub mod public_blockchain;
