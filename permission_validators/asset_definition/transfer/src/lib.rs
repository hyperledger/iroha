//! Validator that checks [`Transfer`] instruction related to asset definitions

#![no_std]
#![no_main]

extern crate alloc;

use iroha_validator::{prelude::*, utils};

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
pub fn validate(authority: <Account as Identifiable>::Id, instruction: InstructionBox) -> Verdict {
    let InstructionBox::Transfer(transfer) = instruction else {
        pass!();
    };

    let IdBox::AssetDefinitionId(asset_definition_id) = transfer.source_id()
        .evaluate(&Context::new())
        .dbg_expect("Failed to evaluate `Transfer` source id") else {
        pass!();
    };

    pass_if!(utils::is_asset_definition_owner(
        &asset_definition_id,
        &authority
    ));

    deny!("Can't transfer asset definition of another account")
}
