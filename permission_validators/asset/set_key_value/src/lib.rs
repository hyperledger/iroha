//! Validator that checks [`SetKeyValue`] instruction
//! related to assets and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_validator::{pass_conditions, prelude::*};

/// Strongly-typed representation of `can_set_key_value_in_user_asset` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset::Owner)]
#[validate(pass_conditions::asset::Owner)]
pub struct CanSetKeyValueInUserAsset {
    asset_id: <Asset as Identifiable>::Id,
}

/// Validate [`SetKeyValue`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_set_key_value_in_user_asset`] permission tokens.
///
/// # [`SetKeyValue`]
///
/// ## Pass
///
/// - [`SetKeyValue`] `object_id` is not an [`AssetId`];
/// - `authority` is an asset owner;
/// - `authority` has a corresponding [`can_set_key_value_in_user_asset`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_set_key_value_in_user_asset`].
///
/// [`can_set_key_value_in_user_asset`]: CanSetKeyValueInUserAsset
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(<CanSetKeyValueInUserAsset>, (authority, instruction));

    let Instruction::SetKeyValue(set_key_value) = instruction else {
        pass!();
    };

    let IdBox::AssetId(asset_id) = set_key_value.object_id()
        .evaluate(&Context::new())
        .dbg_expect("Failed to evaluate `SetKeyValue` object id") else {
        pass!();
    };

    pass_if!(*asset_id.account_id() == authority);
    pass_if!(CanSetKeyValueInUserAsset { asset_id }.is_owned_by(&authority));

    deny!("Can't set value to the asset metadata of another account")
}
