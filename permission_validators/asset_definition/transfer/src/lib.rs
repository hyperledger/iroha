//! Validator that checks [`Transfer`] instruction related to asset definitions

#![no_std]
#![no_main]

extern crate alloc;

use iroha_wasm::{
    data_model::prelude::*,
    debug::DebugExpectExt as _,
    validator::{prelude::*, utils},
};

/// Validate [`Transfer`] instruction
///
/// # [`Transfer`]
///
/// ## Pass
///
/// - [`Transfer`] `source_id` is not an [`AssetDefinitionId`];
/// - `authority` is an asset definition owner;
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    let Instruction::Transfer(transfer) = instruction else {
        pass!();
    };

    let IdBox::AssetDefinitionId(asset_definition_id) = transfer.source_id
        .evaluate()
        .dbg_expect("Failed to evaluate `Transfer` source id") else {
        pass!();
    };

    pass_if!(utils::is_asset_definition_owner(
        &asset_definition_id,
        &authority
    ));

    deny!("Can't transfer asset definition of another account")
}
