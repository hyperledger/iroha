//! Contains [`HasToken`] trait and box container for it
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use super::*;

/// Trait that checks whether a permission token is needed for a certain action.
/// The trait should be implemented by the validator.
pub trait HasToken {
    /// Type of token to check for.
    type Token: PermissionTokenTrait;

    /// Get the token that `authority` should
    /// possess, given the `instruction` they are planning to execute
    /// on the current state of `wsv`
    ///
    /// # Errors
    ///
    /// If it is impossible to deduce the required token
    /// given current data (e.g. non-existent account or inapplicable
    /// instruction)
    fn token(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String>;

    /// Convert this object to a type implementing [`IsAllowed`] trait
    ///
    /// Could not use `impl<H: HasToken> IsAllowed for H`
    /// because of conflicting trait implementations
    fn into_validator(self) -> HasTokenAsValidator<Self>
    where
        Self: Sized,
    {
        HasTokenAsValidator { has_token: self }
    }
}

/// Wrapper for types implementing [`HasToken`]
///
/// Implements [`IsAllowed`] trait so that
/// it's possible to use it in [`JudgeBuilder`](super::judge::builder::Builder)
#[derive(Debug, Display)]
#[display(
    fmt = "Allow if the signer has the corresponding `{}` permission token",
    "H::Token::definition_id()"
)]
pub struct HasTokenAsValidator<H: HasToken> {
    has_token: H,
}

impl<H: HasToken> IsAllowed for HasTokenAsValidator<H> {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let permission_token = match self.has_token.token(authority, instruction, wsv) {
            Ok(concrete_token) => concrete_token.into(),
            Err(err) => {
                return ValidatorVerdict::Deny(format!(
                    "Unable to identify the corresponding permission token: {err}",
                ));
            }
        };

        let contain = match wsv.map_account(authority, |account| {
            wsv.account_permission_tokens(account)
                .contains(&permission_token)
        }) {
            Ok(contain) => contain,
            Err(err) => {
                return ValidatorVerdict::Deny(format!(
                    "Unable to check if the account has the permission token: {err}",
                ));
            }
        };

        if contain {
            ValidatorVerdict::Allow
        } else {
            ValidatorVerdict::Deny(format!(
                "Account does not have the needed permission token: {permission_token}",
            ))
        }
    }
}
