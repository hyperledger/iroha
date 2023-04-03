//! Validator that checks [`SetKeyValue`] instruction
//! related to accounts and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_validator::{pass_conditions, prelude::*};

/// Strongly-typed representation of `can_set_key_value_in_user_account` permission token.
#[derive(Token, Validate, pass_conditions::derive_conversions::account::Owner)]
#[validate(pass_conditions::account::Owner)]
pub struct CanSetKeyValueInUserAccount {
    account_id: <Account as Identifiable>::Id,
}

/// Validate [`SetKeyValue`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_set_key_value_in_user_account`] permission tokens.
///
/// # [`SetKeyValue`]
///
/// ## Pass
///
/// - [`SetKeyValue`] `object_id` is not an [`AccountId`];
/// - `authority` is the account owner;
/// - `authority` has a corresponding [`can_set_key_value_in_user_account`] permission token.
///
/// ## Deny
///
/// If none of the `Pass` conditions are met.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_set_key_value_in_user_account`].
///
/// [`can_set_key_value_in_user_account`]: CanSetKeyValueInUserAccount
pub fn validate(authority: <Account as Identifiable>::Id, instruction: InstructionBox) -> Verdict {
    validate_grant_revoke!(<CanSetKeyValueInUserAccount>, (authority, instruction));

    let InstructionBox::SetKeyValue(set_key_value) = instruction else {
        pass!();
    };

    let IdBox::AccountId(account_id) = set_key_value.object_id()
        .evaluate(&Context::new())
        .dbg_expect("Failed to evaluate `SetKeyValue` object id") else {
        pass!();
    };

    pass_if!(account_id == authority);
    pass_if!(CanSetKeyValueInUserAccount { account_id }.is_owned_by(&authority));

    deny!("Can't set value to the metadata of another account")
}
