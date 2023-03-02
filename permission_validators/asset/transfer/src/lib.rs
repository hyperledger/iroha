//! Validator that checks [`Transfer`] instruction
//! related to assets and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_wasm::{
    data_model::prelude::*,
    debug::DebugExpectExt as _,
    validator::{pass_conditions, prelude::*},
};

/// Strongly-typed representation of `can_transfer_assets_with_definition` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset_definition::Owner)]
#[validate(pass_conditions::asset_definition::Owner)]
pub struct CanTransferAssetsWithDefinition {
    asset_definition_id: <AssetDefinition as Identifiable>::Id,
}

/// Strongly-typed representation of `can_transfer_user_asset` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::asset::Owner)]
#[validate(pass_conditions::asset::Owner)]
pub struct CanTransferUserAsset {
    asset_id: <Asset as Identifiable>::Id,
}

/// Validate [`Transfer`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_transfer_assets_with_definition`] and [`can_transfer_user_asset`] permission tokens.
///
/// # [`Transfer`]
///
/// ## Pass
///
/// - [`Transfer`] `source_id` is not an [`AssetId`];
/// - `authority` is an asset owner;
/// - `authority` has a corresponding [`can_transfer_assets_with_definition`] permission token;
/// - `authority` has a corresponding [`can_transfer_user_asset`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_transfer_assets_with_definition`] and [`can_transfer_user_asset`].
///
/// [`can_transfer_assets_with_definition`]: CanTransferAssetsWithDefinition
/// [`can_transfer_user_asset`]: CanTransferUserAsset
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(<CanTransferAssetsWithDefinition, CanTransferUserAsset>, (authority, instruction));

    let Instruction::Transfer(transfer) = instruction else {
        pass!();
    };

    let IdBox::AssetId(asset_id) = transfer.source_id
        .evaluate()
        .dbg_expect("Failed to evaluate `Transfer` source id") else {
        pass!();
    };

    pass_if!(asset_id.account_id == authority);
    pass_if!(CanTransferAssetsWithDefinition {
        asset_definition_id: asset_id.definition_id.clone()
    }
    .is_owned_by(&authority));
    pass_if!(CanTransferUserAsset { asset_id }.is_owned_by(&authority));

    deny!("Can't transfer assets of another account")
}
