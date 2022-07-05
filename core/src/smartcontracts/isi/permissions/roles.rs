//! Contains traits and function related to roles permission checking

use super::{super::Evaluate, *};

/// Checks the [`GrantBox`] instruction.
pub trait IsGrantAllowed: Debug {
    /// Checks the [`GrantBox`] instruction.
    ///
    /// # Errors
    /// If this validator doesn't approve this Grant instruction.
    fn check(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict;

    fn into_validator(self) -> IsGrantAllowedAsValidator<Self>
    where
        Self: Sized,
    {
        IsGrantAllowedAsValidator {
            is_grant_allowed: self,
        }
    }
}

#[derive(Debug)]
pub struct IsGrantAllowedAsValidator<G: IsGrantAllowed> {
    is_grant_allowed: G,
}

impl<G: IsGrantAllowed> IsAllowed for IsGrantAllowedAsValidator<G> {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if let Instruction::Grant(isi) = instruction {
            self.is_grant_allowed.check(authority, isi, wsv)
        } else {
            ValidatorVerdict::Skip
        }
    }
}

/// Checks the [`RevokeBox`] instruction.
pub trait IsRevokeAllowed: Debug {
    /// Checks the [`RevokeBox`] instruction.
    ///
    /// # Errors
    /// If this validator doesn't approve this Revoke instruction.
    fn check(
        &self,
        authority: &AccountId,
        instruction: &RevokeBox,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict;

    fn into_validator(self) -> IsRevokeAllowedAsValidator<Self>
    where
        Self: Sized,
    {
        IsRevokeAllowedAsValidator {
            is_revoke_allowed: self,
        }
    }
}

#[derive(Debug)]
pub struct IsRevokeAllowedAsValidator<R: IsRevokeAllowed> {
    is_revoke_allowed: R,
}

impl<R: IsRevokeAllowed> IsAllowed for IsRevokeAllowedAsValidator<R> {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if let Instruction::Revoke(isi) = instruction {
            self.is_revoke_allowed.check(authority, isi, wsv)
        } else {
            ValidatorVerdict::Skip
        }
    }
}

/// Used in `unpack_` functions below
macro_rules! unpack {
    ($i:ident, $w:ident, Instruction::$v:ident => $t:ty) => {{
        let operation = if let Instruction::$v(operation) = &$i {
            operation
        } else {
            return Ok(vec![$i]);
        };
        let id =
            if let Value::Id(IdBox::RoleId(id)) = operation.object.evaluate($w, &Context::new())? {
                id
            } else {
                return Ok(vec![$i]);
            };

        let instructions = if let Some(role) = $w.world.roles.get(&id) {
            let destination_id = operation.destination_id.evaluate($w, &Context::new())?;
            role.permissions()
                .cloned()
                .map(|permission_token| <$t>::new(permission_token, destination_id.clone()).into())
                .collect()
        } else {
            Vec::new()
        };
        Ok(instructions)
    }};
}

/// Unpacks instruction if it is Grant of a Role into several Grants
/// fo Permission Token.  If instruction is not Grant of Role, returns
/// it as inly instruction inside the vec.  Should be called before
/// permission checks by validators.
///
/// Semantically means that user can grant a role only if they can
/// grant each of the permission tokens that the role consists of.
///
/// # Errors
/// Evaluation failure of instruction fields.
pub fn unpack_if_role_grant(
    instruction: Instruction,
    wsv: &WorldStateView,
) -> eyre::Result<Vec<Instruction>> {
    unpack!(instruction, wsv, Instruction::Grant => GrantBox)
}

/// Unpack instruction if it is a Revoke of a Role, into several
/// Revocations of Permission Tokens. If the instruction is not a
/// Revoke of Role, returns it as an internal instruction inside the
/// vec.
///
/// This `fn` should be called before permission checks (by
/// validators).
///
/// Semantically: the user can revoke a role only if they can revoke
/// each of the permission tokens that the role consists of of.
///
/// # Errors
/// Evaluation failure of each of the instruction fields.
pub fn unpack_if_role_revoke(
    instruction: Instruction,
    wsv: &WorldStateView,
) -> eyre::Result<Vec<Instruction>> {
    unpack!(instruction, wsv, Instruction::Revoke => RevokeBox)
}
