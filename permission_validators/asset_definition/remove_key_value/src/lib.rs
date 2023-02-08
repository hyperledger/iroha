//! Validator that checks [`RemoveKeyValue`] instruction
//! related to asset definitions and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_wasm::{
    data_model::prelude::*,
    debug::DebugExpectExt as _,
    validator::{pass_conditions, prelude::*, utils},
};

/// Strongly-typed representation of `can_remove_key_value_in_asset_definition` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset_definition::Owner)]
#[validate(pass_conditions::asset_definition::Owner)]
pub struct CanRemoveKeyValueInAssetDefinition {
    asset_definition_id: <AssetDefinition as Identifiable>::Id,
}

/// Validate [`RemoveKeyValue`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_remove_key_value_in_asset_definition`] permission tokens.
///
/// # [`RemoveKeyValue`]
///
/// ## Pass
///
/// - [`RemoveKeyValue`] `object_id` is not an [`AssetDefinitionId`];
/// - `authority` is the asset definition creator;
/// - `authority` has a corresponding [`can_remove_key_value_in_asset_definition`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_remove_key_value_in_asset_definition`].
///
/// [`can_remove_key_value_in_asset_definition`]: CanRemoveKeyValueInAssetDefinition
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(<CanRemoveKeyValueInAssetDefinition>, (authority, instruction));

    let Instruction::RemoveKeyValue(remove_key_value) = instruction else {
        pass!();
    };

    let IdBox::AssetDefinitionId(asset_definition_id) = remove_key_value.object_id()
        .evaluate()
        .dbg_expect("Failed to evaluate `RemoveKeyValue` object id") else {
        pass!();
    };

    pass_if!(utils::is_asset_definition_owner(
        &asset_definition_id,
        &authority
    ));
    pass_if!(CanRemoveKeyValueInAssetDefinition {
        asset_definition_id
    }
    .is_owned_by(&authority));

    deny!("Can't remove value from the asset definition metadata created by another account")
}
