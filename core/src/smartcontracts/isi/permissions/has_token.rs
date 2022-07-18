//! Contains [`HasToken`] trait and box container for it

use super::*;

/// Trait that checks whether a permission token is needed for a certain action.
/// The trait should be implemented by the validator.
pub trait HasToken: Debug {
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
    ) -> std::result::Result<PermissionToken, String>;

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
#[derive(Debug)]
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
            Ok(permission_token) => permission_token,
            Err(err) => {
                return ValidatorVerdict::Deny(format!(
                    "Unable to identify corresponding permission token: {}",
                    err
                ));
            }
        };

        let contain = match wsv.map_account(authority, |account| {
            account.contains_permission(&permission_token)
        }) {
            Ok(contain) => contain,
            Err(err) => {
                return ValidatorVerdict::Deny(format!(
                    "Unable to check if account has permission token: {}",
                    err
                ));
            }
        };

        if contain {
            ValidatorVerdict::Allow
        } else {
            ValidatorVerdict::Deny(format!(
                "Account does not have the needed permission token: {:?}.",
                permission_token
            ))
        }
    }
}
