//! Validator that checks [`RemoveKeyValue`] instruction
//! related to assets and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_validator::{pass_conditions, prelude::*};

/// Strongly-typed representation of `can_remove_key_value_in_user_asset` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset::Owner)]
#[validate(pass_conditions::asset::Owner)]
pub struct CanRemoveKeyValueInUserAsset {
    asset_id: <Asset as Identifiable>::Id,
}

/// Validate [`RemoveKeyValue`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_remove_key_value_in_user_asset`] permission tokens.
///
/// # [`RemoveKeyValue`]
///
/// ## Pass
///
/// - [`RemoveKeyValue`] `object_id` is not an [`AssetId`];
/// - `authority` is an asset owner;
/// - `authority` has a corresponding [`can_remove_key_value_in_user_asset`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_remove_key_value_in_user_asset`].
///
/// [`can_remove_key_value_in_user_asset`]: CanRemoveKeyValueInUserAsset
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(<CanRemoveKeyValueInUserAsset>, (authority, instruction));

    let Instruction::RemoveKeyValue(remove_key_value) = instruction else {
        pass!();
    };

    let IdBox::AssetId(asset_id) = remove_key_value.object_id()
        .evaluate()
        .dbg_expect("Failed to evaluate `RemoveKeyValue` object id") else {
        pass!();
    };

    pass_if!(*asset_id.account_id() == authority);
    pass_if!(CanRemoveKeyValueInUserAsset { asset_id }.is_owned_by(&authority));

    deny!("Can't remove value from the asset metadata of another account")
}
