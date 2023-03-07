//! Validator that checks [`NewParameter`] instruction
//! and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_validator::{pass_conditions, prelude::*};

/// Strongly-typed representation of `can_grant_permission_to_create_parameters` permission token.
#[derive(Token, Validate, Clone, Copy)]
#[validate(pass_conditions::OnlyGenesis)]
pub struct CanGrantPermissionToCreateParameters;

/// Strongly-typed representation of `can_revoke_permission_to_create_parameters` permission token.
#[derive(Token, Validate, Clone, Copy)]
#[validate(pass_conditions::OnlyGenesis)]
pub struct CanRevokePermissionToCreateParameters;

/// Strongly-typed representation of `can_create_parameters` permission token.
#[derive(Token, Clone, Copy)]
pub struct CanCreateParameters;

impl Validate for CanCreateParameters {
    /// Validate [`Grant`] instruction for this token.
    ///
    /// # Pass
    ///
    /// - If `authority` has a corresponding [`can_grant_permission_to_create_parameters`](CanGrantPermissionToCreateParameters) permission token.
    ///
    /// # Deny
    ///
    /// In another case.
    fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
        pass_if!(CanGrantPermissionToCreateParameters.is_owned_by(authority));
        deny!("Can't grant permission to create new configuration parameters without permission from genesis")
    }

    /// Validate [`Grant`] instruction for this token.
    ///
    /// # Pass
    ///
    /// - If `authority` has a corresponding [`can_revoke_permission_to_create_parameters`](CanRevokePermissionToCreateParameters) permission token.
    ///
    /// # Deny
    ///
    /// In another case.
    fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
        pass_if!(CanRevokePermissionToCreateParameters.is_owned_by(authority));
        deny!("Can't revoke permission to create new configuration parameters without permission from genesis")
    }
}

/// Validate [`NewParameter`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_grant_permission_to_new_parameters`], [`can_revoke_permission_to_new_parameters`]
/// and [`can_new_parameters`] permission token.
///
/// # [`NewParameter`]
///
/// ## Pass
///
/// - `authority` has a corresponding [`can_new_parameters`] permission token.
///
/// ## Deny
///
/// In another case.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_grant_permission_to_new_parameters`], [`can_revoke_permission_to_new_parameters`]
/// and [`can_new_parameters`].
///
/// [`can_grant_permission_to_new_parameters`]: CanGrantPermissionToCreateParameters
/// [`can_revoke_permission_to_new_parameters`]: CanRevokePermissionToCreateParameters
/// [`can_new_parameters`]: CanCreateParameters
#[allow(clippy::needless_pass_by_value)]
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(
        <CanGrantPermissionToCreateParameters, CanRevokePermissionToCreateParameters, CanCreateParameters>,
        (authority, instruction)
    );

    let Instruction::NewParameter(_) = instruction else {
        pass!();
    };

    pass_if!(CanCreateParameters.is_owned_by(&authority));

    deny!("Can't create new configuration parameters without permission")
}
