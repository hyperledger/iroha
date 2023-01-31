//! Validator that checks [`Unregister`] instruction
//! related to asset definitions and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_wasm::validator::{pass_conditions, prelude::*, utils};

/// Strongly-typed representation of `can_unregister_asset_definition` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset_definition::Owner)]
#[validate(pass_conditions::asset_definition::Owner)]
pub struct CanUnregisterAssetDefinition {
    asset_definition_id: <AssetDefinition as Identifiable>::Id,
}

/// Validate [`Unregister`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_unregister_asset_definition`] permission token.
///
/// # [`Unregister`]
///
/// ## Pass
///
/// - [`Unregister`] `object_id` is not an [`AssetDefinitionId`]
/// - `authority` is an asset creator;
/// - `authority` has a corresponding [`can_unregister_asset_definition`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_unregister_asset_definition`].
///
/// [`can_unregister_asset_definition`]: CanUnregisterAssetDefinition
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(<CanUnregisterAssetDefinition>, (authority, instruction));

    let Instruction::Unregister(unregister) = instruction else {
        pass!();
    };

    let IdBox::AssetDefinitionId(asset_definition_id) = unregister.object_id
        .evaluate_on_host()
        .dbg_expect("Failed to evaluate `Unregister` object id") else {
        pass!();
    };

    pass_if!(utils::is_asset_definition_owner(
        &asset_definition_id,
        &authority
    ));
    pass_if!(CanUnregisterAssetDefinition {
        asset_definition_id
    }
    .is_owned_by(&authority));

    deny!("Can't unregister assets registered by other accounts")
}
