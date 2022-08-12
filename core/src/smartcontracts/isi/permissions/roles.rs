//! Contains traits and function related to roles permission checking

use super::{super::Evaluate, *};

/// Checks the [`GrantBox`] instruction.
pub trait IsGrantAllowed: Display {
    /// Type of token to check.
    type Token: PermissionTokenTrait;

    /// Check if the authority can grant the permission token.
    ///
    /// # Reasons to deny
    /// If this validator doesn't approve such Grant instruction.
    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict;

    /// Convert this object to a type implementing [`IsAllowed`] trait
    ///
    /// Could not use `impl<G: IsGrantAllowed> IsAllowed for G`
    /// because of conflicting trait implementations
    fn into_validator(self) -> IsGrantAllowedAsValidator<Self>
    where
        Self: Sized,
    {
        IsGrantAllowedAsValidator {
            is_grant_allowed: self,
        }
    }
}

/// Wrapper for types implementing [`IsGrantAllowed`]
///
/// Implements [`IsAllowed`] trait so that
/// it's possible to use it in [`JudgeBuilder`](super::judge::builder::Builder)
#[derive(Debug, Display)]
#[display(
    fmt = "Allow to grant `{}` permission token if `{}`",
    "G::Token::definition_id()",
    is_grant_allowed
)]
pub struct IsGrantAllowedAsValidator<G: IsGrantAllowed + Display> {
    is_grant_allowed: G,
}

impl<G: IsGrantAllowed + Display> IsAllowed for IsGrantAllowedAsValidator<G> {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if let Instruction::Grant(grant) = instruction {
            if let Ok(token) = extract_specialized_token_from_grant::<G::Token>(grant, wsv) {
                return self.is_grant_allowed.check(authority, token, wsv);
            }
        }

        ValidatorVerdict::Skip
    }
}

/// Checks the [`RevokeBox`] instruction.
pub trait IsRevokeAllowed {
    /// Type of token to check.
    type Token: PermissionTokenTrait;

    /// Check if the authority can Revoke the permission token.
    ///
    /// # Reasons to deny
    /// If this validator doesn't approve such Revoke instruction.
    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict;

    /// Convert this object to a type implementing [`IsAllowed`] trait
    ///
    /// Could not use `impl<R: IsGrantAllowed> IsAllowed for R`
    /// because of conflicting trait implementations
    fn into_validator(self) -> IsRevokeAllowedAsValidator<Self>
    where
        Self: Display + Sized,
    {
        IsRevokeAllowedAsValidator {
            is_revoke_allowed: self,
        }
    }
}

/// Wrapper for types implementing [`IsGrantAllowed`]
///
/// Implements [`IsAllowed`] trait so that
/// it's possible to use it in [`JudgeBuilder`](super::judge::builder::Builder)
#[derive(Debug, Display)]
#[display(
    fmt = "Allow to revoke `{}` permission token if `{}`",
    "R::Token::definition_id()",
    is_revoke_allowed
)]
pub struct IsRevokeAllowedAsValidator<R: IsRevokeAllowed + Display> {
    is_revoke_allowed: R,
}

impl<R: IsRevokeAllowed + Display> IsAllowed for IsRevokeAllowedAsValidator<R> {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if let Instruction::Revoke(revoke) = instruction {
            if let Ok(token) = extract_specialized_token_from_revoke::<R::Token>(revoke, wsv) {
                return self.is_revoke_allowed.check(authority, token, wsv);
            }
        }
        ValidatorVerdict::Skip
    }
}

/// Used in `unpack_` functions for role granting and revoking
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

macro_rules! impl_extract_specialized_token {
    (<$isi_type:ty>, $isi:ident, $wsv:ident) => {{
        let value = $isi
            .object
            .evaluate($wsv, &Context::new())
            .map_err(|e| e.to_string())?;

        match value {
            Value::Id(IdBox::RoleId(role_id)) => {
                let role = $wsv
                    .roles()
                    .get(&role_id)
                    .ok_or_else(|| format!("Role with id `{role_id}` not found"))?;
                let specialized_token = role
                    .permissions()
                    .find_map(|permission| T::try_from(permission.clone()).ok())
                    .ok_or_else(|| {
                        format!(
                            "Role {} doesn't contain requested permission token",
                            role.value()
                        )
                    })?;

                Ok(specialized_token)
            }
            Value::PermissionToken(permission_token) => {
                let specialized_token: T = permission_token
                    .try_into()
                    .map_err(|e: PredefinedTokenConversionError| e.to_string())?;

                Ok(specialized_token)
            }
            _ => Err(format!(
                "Provided `{}` instruction contains unsupported object type",
                stringify!($isi_type)
            )),
        }
    }};
}

/// Extract the specialized token from [`GrantBox`]
///
/// # Errors
/// - `instruction` cannot be evaluated;
/// - `instruction` doesn't evaluate to [`RoleId`] or [`PermissionToken`];
/// - There is no such role;
/// - Role doesn't contain requested specialized token;
/// - Generic [`PermissionToken`] cannot be converted to requested specialized token.
fn extract_specialized_token_from_grant<T>(
    instruction: &GrantBox,
    wsv: &WorldStateView,
) -> Result<T>
where
    T: PermissionTokenTrait,
{
    impl_extract_specialized_token!(<GrantBox>, instruction, wsv)
}

/// Extracts specialized token from [`RevokeBox`]
///
/// # Errors
/// - Cannot evaluate `instruction`;
/// - `instruction` doesn't evaluate to [`RoleId`] or [`PermissionToken`];
/// - There is no such role;
/// - Role doesn't contain requested specialized token;
/// - Generic [`PermissionToken`] can't be converted to requested specialized token.
fn extract_specialized_token_from_revoke<T>(
    instruction: &RevokeBox,
    wsv: &WorldStateView,
) -> Result<T>
where
    T: PermissionTokenTrait,
{
    impl_extract_specialized_token!(<RevokeBox>, instruction, wsv)
}
