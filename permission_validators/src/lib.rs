//! Main and default Iroha instruction validator.

#![no_std]
#![no_main]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use iroha_validator::prelude::*;

/// Validate any [`Instruction`](iroha_validator::data_model::isi::InstructionBox).
//
// TODO: Not exhaustive list. Add more validators here.
#[entrypoint(params = "[authority, instruction]")]
pub fn validate(authority: <Account as Identifiable>::Id, instruction: InstructionBox) -> Verdict {
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
        .and_then(|| {
            iroha_parameter_new_validator::validate(authority.clone(), instruction.clone())
        })
        .and_then(|| iroha_parameter_set_validator::validate(authority, instruction))
}
