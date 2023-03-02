//! Validator that checks [`Mint`] instruction
//! related to assets and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_wasm::{
    data_model::prelude::*,
    debug::DebugExpectExt as _,
    validator::{pass_conditions, prelude::*, utils},
};

/// Strongly-typed representation of `can_mint_assets_with_definition` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset_definition::Owner)]
#[validate(pass_conditions::asset_definition::Owner)]
pub struct CanMintAssetsWithDefinition {
    asset_definition_id: <AssetDefinition as Identifiable>::Id,
}

/// Validate [`Mint`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_mint_assets_with_definition`] permission token.
///
/// # [`Mint`]
///
/// ## Pass
///
/// - [`Mint`] `destination_id` is not an [`AssetId`];
/// - `authority` is an asset creator;
/// - `authority` has a corresponding [`can_mint_assets_with_definition`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_mint_assets_with_definition`].
///
/// [`can_mint_assets_with_definition`]: CanMintAssetsWithDefinition
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(<CanMintAssetsWithDefinition>, (authority, instruction));

    let Instruction::Mint(mint) = instruction else {
        pass!();
    };

    let IdBox::AssetId(asset_id) = mint.destination_id
        .evaluate()
        .dbg_expect("Failed to evaluate `Mint` destination id") else {
        pass!();
    };

    pass_if!(utils::is_asset_definition_owner(
        &asset_id.definition_id,
        &authority
    ));
    pass_if!(CanMintAssetsWithDefinition {
        asset_definition_id: asset_id.definition_id
    }
    .is_owned_by(&authority));

    deny!("Can't mint assets with definitions registered by other accounts")
}
