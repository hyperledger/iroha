//! Validator that checks [`Unregister`] instruction
//! related to assets and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_validator::{pass_conditions, prelude::*, utils};

/// Strongly-typed representation of `can_unregister_assets_with_definition` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset_definition::Owner)]
#[validate(pass_conditions::asset_definition::Owner)]
pub struct CanUnregisterAssetsWithDefinition {
    asset_definition_id: <AssetDefinition as Identifiable>::Id,
}

/// Strongly-typed representation of `can_unregister_user_asset` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset::Owner)]
#[validate(pass_conditions::asset::Owner)]
pub struct CanUnregisterUserAsset {
    asset_id: <Asset as Identifiable>::Id,
}

/// Validate [`Unregister`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_unregister_assets_with_definition`] and [`can_unregister_user_asset`] permission tokens.
///
/// # [`Unregister`]
///
/// ## Pass
///
/// - [`Unregister`] `object_id` is not an [`AssetId`]
/// - `authority` is an asset owner;
/// - `authority` is an asset creator;
/// - `authority` has a corresponding [`can_unregister_assets_with_definition`] permission token;
/// - `authority` has a corresponding [`can_unregister_user_asset`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_unregister_assets_with_definition`] and [`can_unregister_user_asset`].
///
/// [`can_unregister_assets_with_definition`]: CanUnregisterAssetsWithDefinition
/// [`can_unregister_user_asset`]: CanUnregisterUserAsset
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(<CanUnregisterUserAsset>, (authority, instruction));

    let Instruction::Unregister(unregister) = instruction else {
        pass!();
    };

    let IdBox::AssetId(asset_id) = unregister.object_id()
        .evaluate(&Context::new())
        .dbg_expect("Failed to evaluate `Unregister` object id") else {
        pass!();
    };

    pass_if!(*asset_id.account_id() == authority);
    pass_if!(utils::is_asset_definition_owner(
        asset_id.definition_id(),
        &authority
    ));
    pass_if!(CanUnregisterAssetsWithDefinition {
        asset_definition_id: asset_id.definition_id().clone()
    }
    .is_owned_by(&authority));
    pass_if!(CanUnregisterUserAsset { asset_id }.is_owned_by(&authority));

    deny!("Can't unregister asset from another account")
}
