//! Validator that checks [`RemoveKeyValue`] instruction
//! related to accounts and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_wasm::{
    data_model::prelude::*,
    debug::DebugExpectExt as _,
    validator::{pass_conditions, prelude::*},
};

/// Strongly-typed representation of `can_remove_key_value_in_user_account` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::account::Owner)]
#[validate(pass_conditions::account::Owner)]
pub struct CanRemoveKeyValueInUserAccount {
    account_id: <Account as Identifiable>::Id,
}

/// Validate [`RemoveKeyValue`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_remove_key_value_in_user_account`] permission tokens.
///
/// # [`RemoveKeyValue`]
///
/// ## Pass
///
/// - [`RemoveKeyValue`] `object_id` is not an [`AccountId`];
/// - `authority` is the account owner;
/// - `authority` has a corresponding [`can_remove_key_value_in_user_account`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_remove_key_value_in_user_account`].
///
/// [`can_remove_key_value_in_user_account`]: CanRemoveKeyValueInUserAccount
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(<CanRemoveKeyValueInUserAccount>, (authority, instruction));

    let Instruction::RemoveKeyValue(remove_key_value) = instruction else {
        pass!();
    };

    let IdBox::AccountId(account_id) = remove_key_value.object_id
        .evaluate()
        .dbg_expect("Failed to evaluate `RemoveKeyValue` object id") else {
        pass!();
    };

    pass_if!(account_id == authority);
    pass_if!(CanRemoveKeyValueInUserAccount { account_id }.is_owned_by(&authority));

    deny!("Can't remove value from the metadata of another account")
}
