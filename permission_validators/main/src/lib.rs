//! Main and default Iroha instruction validator.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_wasm::data_model::prelude::*;

/// Validate any [`Instruction`](iroha_wasm::data_model::isi::Instruction).
//
// TODO: Not exhaustive list. Add more validators here.
#[iroha_wasm::validator::entrypoint(params = "[authority, instruction]")]
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    iroha_asset_burn_validator::validate(authority.clone(), instruction.clone())
        .and_then(|| iroha_asset_mint_validator::validate(authority.clone(), instruction.clone()))
        .and_then(|| {
            iroha_asset_set_key_value_validator::validate(authority.clone(), instruction.clone())
        })
        .and_then(|| {
            iroha_asset_remove_key_value_validator::validate(authority.clone(), instruction.clone())
        })
        .and_then(|| {
            iroha_asset_transfer_validator::validate(authority.clone(), instruction.clone())
        })
        .and_then(|| {
            iroha_asset_unregister_validator::validate(authority.clone(), instruction.clone())
        })
        .and_then(|| {
            iroha_asset_definition_set_key_value_validator::validate(
                authority.clone(),
                instruction.clone(),
            )
        })
        .and_then(|| {
            iroha_asset_definition_remove_key_value_validator::validate(
                authority.clone(),
                instruction.clone(),
            )
        })
        .and_then(|| {
            iroha_asset_definition_unregister_validator::validate(
                authority.clone(),
                instruction.clone(),
            )
        })
        .and_then(|| {
            iroha_asset_definition_transfer_validator::validate(
                authority.clone(),
                instruction.clone(),
            )
        })
        .and_then(|| {
            iroha_account_set_key_value_validator::validate(authority.clone(), instruction.clone())
        })
        .and_then(|| {
            iroha_account_remove_key_value_validator::validate(
                authority.clone(),
                instruction.clone(),
            )
        })
        .and_then(|| iroha_parameter_set_validator::validate(authority, instruction))
}
