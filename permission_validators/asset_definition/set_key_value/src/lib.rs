//! Validator that checks [`SetKeyValue`] instruction
//! related to asset definitions and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_validator::{pass_conditions, prelude::*, utils};

/// Strongly-typed representation of `can_set_key_value_in_asset_definition` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset_definition::Owner)]
#[validate(pass_conditions::asset_definition::Owner)]
pub struct CanSetKeyValueInAssetDefinition {
    asset_definition_id: <AssetDefinition as Identifiable>::Id,
}

/// Validate [`SetKeyValue`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_set_key_value_in_asset_definition`] permission tokens.
///
/// # [`SetKeyValue`]
///
/// ## Pass
///
/// - [`SetKeyValue`] `object_id` is not an [`AssetDefinitionId`];
/// - `authority` is the asset definition creator;
/// - `authority` has a corresponding [`can_set_key_value_in_asset_definition`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_set_key_value_in_asset_definition`].
///
/// [`can_set_key_value_in_asset_definition`]: CanSetKeyValueInAssetDefinition
pub fn validate(authority: <Account as Identifiable>::Id, instruction: InstructionBox) -> Verdict {
    validate_grant_revoke!(<CanSetKeyValueInAssetDefinition>, (authority, instruction));

    let InstructionBox::SetKeyValue(set_key_value) = instruction else {
        pass!();
    };

    let IdBox::AssetDefinitionId(asset_definition_id) = set_key_value.object_id()
        .evaluate(&Context::new())
        .dbg_expect("Failed to evaluate `SetKeyValue` object id") else {
        pass!();
    };

    pass_if!(utils::is_asset_definition_owner(
        &asset_definition_id,
        &authority
    ));
    pass_if!(CanSetKeyValueInAssetDefinition {
        asset_definition_id
    }
    .is_owned_by(&authority));

    deny!("Can't set value to the asset definition metadata created by another account")
}
