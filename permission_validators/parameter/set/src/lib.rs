//! Validator that checks [`SetParameter`] instruction
//! and respective [`Grant`] and [`Revoke`] instructions.

#![no_std]
#![no_main]

extern crate alloc;

use iroha_validator::{pass_conditions, prelude::*};

/// Strongly-typed representation of `can_grant_permission_to_set_parameters` permission token.
#[derive(Token, Validate, Clone, Copy)]
#[validate(pass_conditions::OnlyGenesis)]
pub struct CanGrantPermissionToSetParameters;

/// Strongly-typed representation of `can_revoke_permission_to_set_parameters` permission token.
#[derive(Token, Validate, Clone, Copy)]
#[validate(pass_conditions::OnlyGenesis)]
pub struct CanRevokePermissionToSetParameters;

/// Strongly-typed representation of `can_set_parameters` permission token.
#[derive(Token, Clone, Copy)]
pub struct CanSetParameters;

impl Validate for CanSetParameters {
    /// Validate [`Grant`] instruction for this token.
    ///
    /// # Pass
    ///
    /// - If `authority` has a corresponding [`can_grant_permission_to_set_parameters`](CanGrantPermissionToSetParameters) permission token.
    ///
    /// # Deny
    ///
    /// In another case.
    fn validate_grant(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
        pass_if!(CanGrantPermissionToSetParameters.is_owned_by(authority));
        deny!("Can't grant permission to set configuration parameters without permission from genesis")
    }

    /// Validate [`Grant`] instruction for this token.
    ///
    /// # Pass
    ///
    /// - If `authority` has a corresponding [`can_revoke_permission_to_set_parameters`](CanRevokePermissionToSetParameters) permission token.
    ///
    /// # Deny
    ///
    /// In another case.
    fn validate_revoke(&self, authority: &<Account as Identifiable>::Id) -> Verdict {
        pass_if!(CanRevokePermissionToSetParameters.is_owned_by(authority));
        deny!("Can't revoke permission to set configuration parameters without permission from genesis")
    }
}

/// Validate [`SetParameter`] instruction as well as [`Grant`] and [`Revoke`] instructions for
/// [`can_grant_permission_to_set_parameters`], [`can_revoke_permission_to_set_parameters`]
/// and [`can_set_parameters`] permission token.
///
/// # [`SetParameter`]
///
/// ## Pass
///
/// - `authority` has a corresponding [`can_set_parameters`] permission token.
///
/// ## Deny
///
/// In another case.
///
/// # [`Grant`] and [`Revoke`]
///
/// For more details about [`Grant`] and [`Revoke`] instructions validation,
/// see [`can_grant_permission_to_set_parameters`], [`can_revoke_permission_to_set_parameters`]
/// and [`can_set_parameters`].
///
/// [`can_grant_permission_to_set_parameters`]: CanGrantPermissionToSetParameters
/// [`can_revoke_permission_to_set_parameters`]: CanRevokePermissionToSetParameters
/// [`can_set_parameters`]: CanSetParameters
#[allow(clippy::needless_pass_by_value)]
pub fn validate(authority: <Account as Identifiable>::Id, instruction: Instruction) -> Verdict {
    validate_grant_revoke!(
        <CanGrantPermissionToSetParameters, CanRevokePermissionToSetParameters, CanSetParameters>,
        (authority, instruction)
    );

    let Instruction::SetParameter(_) = instruction else {
        pass!();
    };

    pass_if!(CanSetParameters.is_owned_by(&authority));

    deny!("Can't set configuration parameters without permission")
}
