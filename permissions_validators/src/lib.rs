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

// I need to put these modules after the macro definitions.
pub mod private_blockchain;
pub mod public_blockchain;
